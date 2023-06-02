use :: c2rust_bitfields;
use :: libc;
extern "C" {
    fn snprintf(_: *mut i8, _: u64, _: *const i8, _: ...) -> i32;
    fn sscanf(_: *const i8, _: *const i8, _: ...) -> i32;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memmove(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn fabs(_: f64) -> f64;
    fn floor(_: f64) -> f64;
    fn xmlHashCreate(size: i32) -> *mut crate::src::xmlsave::_xmlHashTable;
    fn xmlHashFree(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        f: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>,
    );
    fn xmlHashAddEntry2(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
        name2: *const u8,
        userdata: *mut core::ffi::c_void,
    ) -> i32;
    fn xmlHashLookup2(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
        name2: *const u8,
    ) -> *mut core::ffi::c_void;
    fn __xmlSimpleError(
        domain: i32,
        code: i32,
        node: *mut crate::src::threads::_xmlNode,
        msg: *const i8,
        extra: *const i8,
    );
    fn xmlGetDocEntity(
        doc: *const crate::src::threads::_xmlDoc,
        name: *const u8,
    ) -> *mut crate::src::threads::_xmlEntity;
    fn labs(_: i64) -> i64;
    static mut xmlMalloc: Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
    static mut xmlMallocAtomic: Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
    static mut xmlFree: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
    fn __xmlGenericError(
    ) -> *mut Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
    fn __xmlGenericErrorContext() -> *mut *mut core::ffi::c_void;
    static mut xmlXPathNAN: f64;
    static mut xmlXPathPINF: f64;
    static mut xmlXPathNINF: f64;
    fn xmlXPathIsNaN(val: f64) -> i32;
}
pub use crate::src::tree::xmlSearchNs;
pub use crate::src::tree::xmlSplitQName2;
pub use crate::src::tree::xmlValidateNCName;
pub use crate::src::tree::xmlValidateNMToken;
pub use crate::src::tree::xmlValidateName;
pub use crate::src::tree::xmlValidateQName;
pub use crate::src::uri::xmlFreeURI;
pub use crate::src::uri::xmlParseURI;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::valid::xmlAddID;
pub use crate::src::valid::xmlAddRef;
pub use crate::src::valid::xmlValidateNotationUse;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::xmlregexp::_xmlRegexp;
pub use crate::src::xmlregexp::xmlRegexpExec;
pub use crate::src::xmlsave::_xmlHashTable;
pub use crate::src::xmlschemas::xmlSchemaFreeType;
pub use crate::src::xmlschemas::xmlSchemaFreeWildcard;
pub use crate::src::xmlschemas::xmlSchemaNewFacet;
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrcat;
pub use crate::src::xmlstring::xmlStrcmp;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrndup;
pub use crate::src::xmlstring::xmlUTF8Strlen;
pub use crate::src::xpointer::_xmlDict;
pub type xmlChar = u8;
pub type size_t = u64;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
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
pub type xmlAttrPtr = *mut crate::src::threads::_xmlAttr;
pub type xmlAttr = crate::src::threads::_xmlAttr;
pub type xmlNodePtr = *mut crate::src::threads::_xmlNode;
pub type xmlNode = crate::src::threads::_xmlNode;
pub type xmlHashTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlHashTable = crate::src::xmlsave::_xmlHashTable;
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
pub type xmlRegexp = crate::src::xmlregexp::_xmlRegexp;
pub type xmlRegexpPtr = *mut crate::src::xmlregexp::_xmlRegexp;
pub type xmlNsPtr = *mut crate::src::threads::_xmlNs;
pub type _xmlID<'a> = crate::src::tree::_xmlID<'a>;
pub type xmlID<'a> = crate::src::tree::_xmlID<'a>;
pub type xmlIDPtr<'a> = *mut crate::src::tree::_xmlID<'a>;
pub type _xmlRef<'a> = crate::src::valid::_xmlRef<'a>;
pub type xmlRef<'a> = crate::src::valid::_xmlRef<'a>;
pub type xmlRefPtr<'a> = *mut crate::src::valid::_xmlRef<'a>;
pub type xmlHashDeallocator =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>;
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
pub type xmlValidCtxtPtr = *mut crate::src::tree::_xmlValidCtxt;
pub type _xmlURI = crate::src::uri::_xmlURI;
pub type xmlURI = crate::src::uri::_xmlURI;
pub type xmlURIPtr = *mut crate::src::uri::_xmlURI;
pub type xmlSchemaAnnotPtr = *mut crate::src::xmlschemas::_xmlSchemaAnnot;
pub type xmlSchemaAnnot = crate::src::xmlschemas::_xmlSchemaAnnot;
pub type _xmlSchemaAnnot = crate::src::xmlschemas::_xmlSchemaAnnot;
pub type xmlSchemaValType = u32;
pub const XML_SCHEMAS_ANYSIMPLETYPE: xmlSchemaValType = 46;
pub const XML_SCHEMAS_ANYTYPE: xmlSchemaValType = 45;
pub const XML_SCHEMAS_BASE64BINARY: xmlSchemaValType = 44;
pub const XML_SCHEMAS_HEXBINARY: xmlSchemaValType = 43;
pub const XML_SCHEMAS_UBYTE: xmlSchemaValType = 42;
pub const XML_SCHEMAS_BYTE: xmlSchemaValType = 41;
pub const XML_SCHEMAS_USHORT: xmlSchemaValType = 40;
pub const XML_SCHEMAS_SHORT: xmlSchemaValType = 39;
pub const XML_SCHEMAS_ULONG: xmlSchemaValType = 38;
pub const XML_SCHEMAS_LONG: xmlSchemaValType = 37;
pub const XML_SCHEMAS_UINT: xmlSchemaValType = 36;
pub const XML_SCHEMAS_INT: xmlSchemaValType = 35;
pub const XML_SCHEMAS_PINTEGER: xmlSchemaValType = 34;
pub const XML_SCHEMAS_NNINTEGER: xmlSchemaValType = 33;
pub const XML_SCHEMAS_NINTEGER: xmlSchemaValType = 32;
pub const XML_SCHEMAS_NPINTEGER: xmlSchemaValType = 31;
pub const XML_SCHEMAS_INTEGER: xmlSchemaValType = 30;
pub const XML_SCHEMAS_ANYURI: xmlSchemaValType = 29;
pub const XML_SCHEMAS_NOTATION: xmlSchemaValType = 28;
pub const XML_SCHEMAS_ENTITIES: xmlSchemaValType = 27;
pub const XML_SCHEMAS_ENTITY: xmlSchemaValType = 26;
pub const XML_SCHEMAS_IDREFS: xmlSchemaValType = 25;
pub const XML_SCHEMAS_IDREF: xmlSchemaValType = 24;
pub const XML_SCHEMAS_ID: xmlSchemaValType = 23;
pub const XML_SCHEMAS_NCNAME: xmlSchemaValType = 22;
pub const XML_SCHEMAS_QNAME: xmlSchemaValType = 21;
pub const XML_SCHEMAS_NAME: xmlSchemaValType = 20;
pub const XML_SCHEMAS_NMTOKENS: xmlSchemaValType = 19;
pub const XML_SCHEMAS_NMTOKEN: xmlSchemaValType = 18;
pub const XML_SCHEMAS_LANGUAGE: xmlSchemaValType = 17;
pub const XML_SCHEMAS_TOKEN: xmlSchemaValType = 16;
pub const XML_SCHEMAS_BOOLEAN: xmlSchemaValType = 15;
pub const XML_SCHEMAS_DOUBLE: xmlSchemaValType = 14;
pub const XML_SCHEMAS_FLOAT: xmlSchemaValType = 13;
pub const XML_SCHEMAS_DURATION: xmlSchemaValType = 12;
pub const XML_SCHEMAS_DATETIME: xmlSchemaValType = 11;
pub const XML_SCHEMAS_DATE: xmlSchemaValType = 10;
pub const XML_SCHEMAS_GYEARMONTH: xmlSchemaValType = 9;
pub const XML_SCHEMAS_GYEAR: xmlSchemaValType = 8;
pub const XML_SCHEMAS_GMONTHDAY: xmlSchemaValType = 7;
pub const XML_SCHEMAS_GMONTH: xmlSchemaValType = 6;
pub const XML_SCHEMAS_GDAY: xmlSchemaValType = 5;
pub const XML_SCHEMAS_TIME: xmlSchemaValType = 4;
pub const XML_SCHEMAS_DECIMAL: xmlSchemaValType = 3;
pub const XML_SCHEMAS_NORMSTRING: xmlSchemaValType = 2;
pub const XML_SCHEMAS_STRING: xmlSchemaValType = 1;
pub const XML_SCHEMAS_UNKNOWN: xmlSchemaValType = 0;
pub type xmlSchemaTypeType = u32;
pub const XML_SCHEMA_EXTRA_ATTR_USE_PROHIB: xmlSchemaTypeType = 2001;
pub const XML_SCHEMA_EXTRA_QNAMEREF: xmlSchemaTypeType = 2000;
pub const XML_SCHEMA_FACET_MINLENGTH: xmlSchemaTypeType = 1011;
pub const XML_SCHEMA_FACET_MAXLENGTH: xmlSchemaTypeType = 1010;
pub const XML_SCHEMA_FACET_LENGTH: xmlSchemaTypeType = 1009;
pub const XML_SCHEMA_FACET_WHITESPACE: xmlSchemaTypeType = 1008;
pub const XML_SCHEMA_FACET_ENUMERATION: xmlSchemaTypeType = 1007;
pub const XML_SCHEMA_FACET_PATTERN: xmlSchemaTypeType = 1006;
pub const XML_SCHEMA_FACET_FRACTIONDIGITS: xmlSchemaTypeType = 1005;
pub const XML_SCHEMA_FACET_TOTALDIGITS: xmlSchemaTypeType = 1004;
pub const XML_SCHEMA_FACET_MAXEXCLUSIVE: xmlSchemaTypeType = 1003;
pub const XML_SCHEMA_FACET_MAXINCLUSIVE: xmlSchemaTypeType = 1002;
pub const XML_SCHEMA_FACET_MINEXCLUSIVE: xmlSchemaTypeType = 1001;
pub const XML_SCHEMA_FACET_MININCLUSIVE: xmlSchemaTypeType = 1000;
pub const XML_SCHEMA_TYPE_ATTRIBUTE_USE: xmlSchemaTypeType = 26;
pub const XML_SCHEMA_TYPE_PARTICLE: xmlSchemaTypeType = 25;
pub const XML_SCHEMA_TYPE_IDC_KEYREF: xmlSchemaTypeType = 24;
pub const XML_SCHEMA_TYPE_IDC_KEY: xmlSchemaTypeType = 23;
pub const XML_SCHEMA_TYPE_IDC_UNIQUE: xmlSchemaTypeType = 22;
pub const XML_SCHEMA_TYPE_ANY_ATTRIBUTE: xmlSchemaTypeType = 21;
pub const XML_SCHEMA_TYPE_UNION: xmlSchemaTypeType = 20;
pub const XML_SCHEMA_TYPE_LIST: xmlSchemaTypeType = 19;
pub const XML_SCHEMA_TYPE_NOTATION: xmlSchemaTypeType = 18;
pub const XML_SCHEMA_TYPE_GROUP: xmlSchemaTypeType = 17;
pub const XML_SCHEMA_TYPE_ATTRIBUTEGROUP: xmlSchemaTypeType = 16;
pub const XML_SCHEMA_TYPE_ATTRIBUTE: xmlSchemaTypeType = 15;
pub const XML_SCHEMA_TYPE_ELEMENT: xmlSchemaTypeType = 14;
pub const XML_SCHEMA_TYPE_EXTENSION: xmlSchemaTypeType = 13;
pub const XML_SCHEMA_TYPE_RESTRICTION: xmlSchemaTypeType = 12;
pub const XML_SCHEMA_TYPE_UR: xmlSchemaTypeType = 11;
pub const XML_SCHEMA_TYPE_COMPLEX_CONTENT: xmlSchemaTypeType = 10;
pub const XML_SCHEMA_TYPE_SIMPLE_CONTENT: xmlSchemaTypeType = 9;
pub const XML_SCHEMA_TYPE_ALL: xmlSchemaTypeType = 8;
pub const XML_SCHEMA_TYPE_CHOICE: xmlSchemaTypeType = 7;
pub const XML_SCHEMA_TYPE_SEQUENCE: xmlSchemaTypeType = 6;
pub const XML_SCHEMA_TYPE_COMPLEX: xmlSchemaTypeType = 5;
pub const XML_SCHEMA_TYPE_SIMPLE: xmlSchemaTypeType = 4;
pub const XML_SCHEMA_TYPE_FACET: xmlSchemaTypeType = 3;
pub const XML_SCHEMA_TYPE_ANY: xmlSchemaTypeType = 2;
pub const XML_SCHEMA_TYPE_BASIC: xmlSchemaTypeType = 1;
pub type xmlSchemaContentType = u32;
pub const XML_SCHEMA_CONTENT_ANY: xmlSchemaContentType = 7;
pub const XML_SCHEMA_CONTENT_BASIC: xmlSchemaContentType = 6;
pub const XML_SCHEMA_CONTENT_MIXED_OR_ELEMENTS: xmlSchemaContentType = 5;
pub const XML_SCHEMA_CONTENT_SIMPLE: xmlSchemaContentType = 4;
pub const XML_SCHEMA_CONTENT_MIXED: xmlSchemaContentType = 3;
pub const XML_SCHEMA_CONTENT_ELEMENTS: xmlSchemaContentType = 2;
pub const XML_SCHEMA_CONTENT_EMPTY: xmlSchemaContentType = 1;
pub const XML_SCHEMA_CONTENT_UNKNOWN: xmlSchemaContentType = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchemaVal {
    pub type_0: u32,
    pub next: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    pub value: crate::src::xmlschemastypes::C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub decimal: xmlSchemaValDecimal,
    pub date: xmlSchemaValDate,
    pub dur: xmlSchemaValDuration,
    pub qname: xmlSchemaValQName,
    pub hex: xmlSchemaValHex,
    pub base64: xmlSchemaValBase64,
    pub f: f32,
    pub d: f64,
    pub b: i32,
    pub str_0: *mut xmlChar,
}
pub type xmlSchemaValBase64 = crate::src::xmlschemastypes::_xmlSchemaValBase64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchemaValBase64 {
    pub str_0: *mut u8,
    pub total: u32,
}
impl _xmlSchemaValBase64 {
    pub const fn new() -> Self {
        _xmlSchemaValBase64 {
            str_0: (0 as *mut u8),
            total: 0,
        }
    }
}
impl std::default::Default for _xmlSchemaValBase64 {
    fn default() -> Self {
        _xmlSchemaValBase64::new()
    }
}
pub type xmlSchemaValHex = crate::src::xmlschemastypes::_xmlSchemaValHex;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchemaValHex {
    pub str_0: *mut u8,
    pub total: u32,
}
impl _xmlSchemaValHex {
    pub const fn new() -> Self {
        _xmlSchemaValHex {
            str_0: (0 as *mut u8),
            total: 0,
        }
    }
}
impl std::default::Default for _xmlSchemaValHex {
    fn default() -> Self {
        _xmlSchemaValHex::new()
    }
}
pub type xmlSchemaValQName = crate::src::xmlschemastypes::_xmlSchemaValQName;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchemaValQName {
    pub name: *mut u8,
    pub uri: *mut u8,
}
impl _xmlSchemaValQName {
    pub const fn new() -> Self {
        _xmlSchemaValQName {
            name: (0 as *mut u8),
            uri: (0 as *mut u8),
        }
    }
}
impl std::default::Default for _xmlSchemaValQName {
    fn default() -> Self {
        _xmlSchemaValQName::new()
    }
}
pub type xmlSchemaValDuration = crate::src::xmlschemastypes::_xmlSchemaValDuration;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchemaValDuration {
    pub mon: i64,
    pub day: i64,
    pub sec: f64,
}
impl _xmlSchemaValDuration {
    pub const fn new() -> Self {
        _xmlSchemaValDuration {
            mon: 0,
            day: 0,
            sec: 0.0,
        }
    }
}
impl std::default::Default for _xmlSchemaValDuration {
    fn default() -> Self {
        _xmlSchemaValDuration::new()
    }
}
pub type xmlSchemaValDate = crate::src::xmlschemastypes::_xmlSchemaValDate;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchemaValDate {
    pub year: i64,
    pub mon_day_hour_min: [u8; 3],
    pub c2rust_padding: [u8; 5],
    pub sec: f64,
    pub tz_flag_tzo: [u8; 2],
    pub c2rust_padding_0: [u8; 6],
}
impl _xmlSchemaValDate {
    pub const fn new() -> Self {
        _xmlSchemaValDate {
            year: 0,
            mon_day_hour_min: [0, 0, 0],
            c2rust_padding: [0, 0, 0, 0, 0],
            sec: 0.0,
            tz_flag_tzo: [0, 0],
            c2rust_padding_0: [0, 0, 0, 0, 0, 0],
        }
    }
}
impl std::default::Default for _xmlSchemaValDate {
    fn default() -> Self {
        _xmlSchemaValDate::new()
    }
}
impl _xmlSchemaValDate {
    #[doc = r" This method allows you to write to a bitfield with a value"]
    pub fn set_mon(&mut self, int: u32) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.mon_day_hour_min;
        let (lhs_bit, rhs_bit) = (0usize, 3usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    #[doc = r" This method allows you to read from a bitfield to a value"]
    pub fn mon(&self) -> u32 {
        use c2rust_bitfields::FieldType;
        let field = &self.mon_day_hour_min;
        let (lhs_bit, rhs_bit) = (0usize, 3usize);
        <u32 as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    #[doc = r" This method allows you to write to a bitfield with a value"]
    pub fn set_day(&mut self, int: u32) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.mon_day_hour_min;
        let (lhs_bit, rhs_bit) = (4usize, 8usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    #[doc = r" This method allows you to read from a bitfield to a value"]
    pub fn day(&self) -> u32 {
        use c2rust_bitfields::FieldType;
        let field = &self.mon_day_hour_min;
        let (lhs_bit, rhs_bit) = (4usize, 8usize);
        <u32 as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    #[doc = r" This method allows you to write to a bitfield with a value"]
    pub fn set_hour(&mut self, int: u32) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.mon_day_hour_min;
        let (lhs_bit, rhs_bit) = (9usize, 13usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    #[doc = r" This method allows you to read from a bitfield to a value"]
    pub fn hour(&self) -> u32 {
        use c2rust_bitfields::FieldType;
        let field = &self.mon_day_hour_min;
        let (lhs_bit, rhs_bit) = (9usize, 13usize);
        <u32 as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    #[doc = r" This method allows you to write to a bitfield with a value"]
    pub fn set_min(&mut self, int: u32) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.mon_day_hour_min;
        let (lhs_bit, rhs_bit) = (14usize, 19usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    #[doc = r" This method allows you to read from a bitfield to a value"]
    pub fn min(&self) -> u32 {
        use c2rust_bitfields::FieldType;
        let field = &self.mon_day_hour_min;
        let (lhs_bit, rhs_bit) = (14usize, 19usize);
        <u32 as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    #[doc = r" This method allows you to write to a bitfield with a value"]
    pub fn set_tz_flag(&mut self, int: u32) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.tz_flag_tzo;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    #[doc = r" This method allows you to read from a bitfield to a value"]
    pub fn tz_flag(&self) -> u32 {
        use c2rust_bitfields::FieldType;
        let field = &self.tz_flag_tzo;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <u32 as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    #[doc = r" This method allows you to write to a bitfield with a value"]
    pub fn set_tzo(&mut self, int: i32) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.tz_flag_tzo;
        let (lhs_bit, rhs_bit) = (1usize, 12usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    #[doc = r" This method allows you to read from a bitfield to a value"]
    pub fn tzo(&self) -> i32 {
        use c2rust_bitfields::FieldType;
        let field = &self.tz_flag_tzo;
        let (lhs_bit, rhs_bit) = (1usize, 12usize);
        <i32 as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
pub type xmlSchemaValDecimal = crate::src::xmlschemastypes::_xmlSchemaValDecimal;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchemaValDecimal {
    pub lo: u64,
    pub mi: u64,
    pub hi: u64,
    pub extra: u32,
    pub sign_frac_total: [u8; 2],
    pub c2rust_padding: [u8; 2],
}
impl _xmlSchemaValDecimal {
    pub const fn new() -> Self {
        _xmlSchemaValDecimal {
            lo: 0,
            mi: 0,
            hi: 0,
            extra: 0,
            sign_frac_total: [0, 0],
            c2rust_padding: [0, 0],
        }
    }
}
impl std::default::Default for _xmlSchemaValDecimal {
    fn default() -> Self {
        _xmlSchemaValDecimal::new()
    }
}
impl _xmlSchemaValDecimal {
    #[doc = r" This method allows you to write to a bitfield with a value"]
    pub fn set_sign(&mut self, int: u32) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.sign_frac_total;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    #[doc = r" This method allows you to read from a bitfield to a value"]
    pub fn sign(&self) -> u32 {
        use c2rust_bitfields::FieldType;
        let field = &self.sign_frac_total;
        let (lhs_bit, rhs_bit) = (0usize, 0usize);
        <u32 as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    #[doc = r" This method allows you to write to a bitfield with a value"]
    pub fn set_frac(&mut self, int: u32) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.sign_frac_total;
        let (lhs_bit, rhs_bit) = (1usize, 7usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    #[doc = r" This method allows you to read from a bitfield to a value"]
    pub fn frac(&self) -> u32 {
        use c2rust_bitfields::FieldType;
        let field = &self.sign_frac_total;
        let (lhs_bit, rhs_bit) = (1usize, 7usize);
        <u32 as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
    #[doc = r" This method allows you to write to a bitfield with a value"]
    pub fn set_total(&mut self, int: u32) {
        use c2rust_bitfields::FieldType;
        let field = &mut self.sign_frac_total;
        let (lhs_bit, rhs_bit) = (8usize, 15usize);
        int.set_field(field, (lhs_bit, rhs_bit));
    }
    #[doc = r" This method allows you to read from a bitfield to a value"]
    pub fn total(&self) -> u32 {
        use c2rust_bitfields::FieldType;
        let field = &self.sign_frac_total;
        let (lhs_bit, rhs_bit) = (8usize, 15usize);
        <u32 as FieldType>::get_field(field, (lhs_bit, rhs_bit))
    }
}
pub type xmlSchemaVal = crate::src::xmlschemastypes::_xmlSchemaVal;
pub type xmlSchemaValPtr = *mut crate::src::xmlschemastypes::_xmlSchemaVal;
pub type _xmlSchemaType<'a> = crate::src::xmlschemas::_xmlSchemaType<'a>;
pub type xmlSchemaTypePtr<'a> = *mut crate::src::xmlschemas::_xmlSchemaType<'a>;
pub type xmlSchemaType<'a> = crate::src::xmlschemas::_xmlSchemaType<'a>;
pub type xmlSchemaFacetLinkPtr<'a> = *mut crate::src::xmlschemas::_xmlSchemaFacetLink<'a>;
pub type xmlSchemaFacetLink<'a> = crate::src::xmlschemas::_xmlSchemaFacetLink<'a>;
pub type _xmlSchemaFacetLink<'a> = crate::src::xmlschemas::_xmlSchemaFacetLink<'a>;
pub type xmlSchemaFacetPtr<'a> = *mut crate::src::xmlschemas::_xmlSchemaFacet<'a>;
pub type xmlSchemaFacet<'a> = crate::src::xmlschemas::_xmlSchemaFacet<'a>;
pub type _xmlSchemaFacet<'a> = crate::src::xmlschemas::_xmlSchemaFacet<'a>;
pub type xmlSchemaTypeLinkPtr<'a> = *mut crate::src::xmlschemas::_xmlSchemaTypeLink<'a>;
pub type xmlSchemaTypeLink<'a> = crate::src::xmlschemas::_xmlSchemaTypeLink<'a>;
pub type _xmlSchemaTypeLink<'a> = crate::src::xmlschemas::_xmlSchemaTypeLink<'a>;
pub type xmlSchemaWildcardPtr<'a> = *mut crate::src::xmlschemas::_xmlSchemaWildcard<'a>;
pub type xmlSchemaWildcard<'a> = crate::src::xmlschemas::_xmlSchemaWildcard<'a>;
pub type _xmlSchemaWildcard<'a> = crate::src::xmlschemas::_xmlSchemaWildcard<'a>;
pub type xmlSchemaWildcardNsPtr = *mut crate::src::xmlschemas::_xmlSchemaWildcardNs;
pub type xmlSchemaWildcardNs = crate::src::xmlschemas::_xmlSchemaWildcardNs;
pub type _xmlSchemaWildcardNs = crate::src::xmlschemas::_xmlSchemaWildcardNs;
pub type xmlSchemaAttributeLinkPtr<'a> = *mut crate::src::xmlschemas::_xmlSchemaAttributeLink<'a>;
pub type xmlSchemaAttributeLink<'a> = crate::src::xmlschemas::_xmlSchemaAttributeLink<'a>;
pub type _xmlSchemaAttributeLink<'a> = crate::src::xmlschemas::_xmlSchemaAttributeLink<'a>;
pub type _xmlSchemaAttribute<'a> = crate::src::xmlschemas::_xmlSchemaAttribute<'a>;
pub type xmlSchemaAttributePtr<'a> = *mut crate::src::xmlschemas::_xmlSchemaAttribute<'a>;
pub type xmlSchemaAttribute<'a> = crate::src::xmlschemas::_xmlSchemaAttribute<'a>;
pub type xmlSchemaWhitespaceValueType = u32;
pub const XML_SCHEMA_WHITESPACE_COLLAPSE: xmlSchemaWhitespaceValueType = 3;
pub const XML_SCHEMA_WHITESPACE_REPLACE: xmlSchemaWhitespaceValueType = 2;
pub const XML_SCHEMA_WHITESPACE_PRESERVE: xmlSchemaWhitespaceValueType = 1;
pub const XML_SCHEMA_WHITESPACE_UNKNOWN: xmlSchemaWhitespaceValueType = 0;
pub type xmlSchemaTreeItemPtr = *mut crate::src::xmlschemas::_xmlSchemaTreeItem;
pub type xmlSchemaTreeItem = crate::src::xmlschemas::_xmlSchemaTreeItem;
pub type _xmlSchemaTreeItem = crate::src::xmlschemas::_xmlSchemaTreeItem;
pub type xmlSchemaParticlePtr = *mut crate::src::xmlschemas::_xmlSchemaParticle;
pub type xmlSchemaParticle = crate::src::xmlschemas::_xmlSchemaParticle;
pub type _xmlSchemaParticle = crate::src::xmlschemas::_xmlSchemaParticle;
pub type xmlSchemaModelGroupPtr<'a> = *mut crate::src::xmlschemas::_xmlSchemaModelGroup<'a>;
pub type xmlSchemaModelGroup<'a> = crate::src::xmlschemas::_xmlSchemaModelGroup<'a>;
pub type _xmlSchemaModelGroup<'a> = crate::src::xmlschemas::_xmlSchemaModelGroup<'a>;
pub type xmlSchemaValDatePtr = *mut crate::src::xmlschemastypes::_xmlSchemaValDate;
pub type xmlSchemaValDurationPtr = *mut crate::src::xmlschemastypes::_xmlSchemaValDuration;
static mut xmlSchemaTypesInitialized: i32 = 0 as i32;
static mut xmlSchemaTypesBank: *mut crate::src::xmlsave::_xmlHashTable =
    0 as *const xmlHashTable as xmlHashTablePtr;
static mut xmlSchemaTypeStringDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeAnyTypeDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeAnySimpleTypeDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeDecimalDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeDatetimeDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeDateDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeTimeDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeGYearDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeGYearMonthDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeGDayDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeGMonthDayDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeGMonthDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeDurationDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeFloatDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeBooleanDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeDoubleDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeHexBinaryDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeBase64BinaryDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeAnyURIDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypePositiveIntegerDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeNonPositiveIntegerDef: *mut crate::src::xmlschemas::_xmlSchemaType<
    'static,
> = 0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeNegativeIntegerDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeNonNegativeIntegerDef: *mut crate::src::xmlschemas::_xmlSchemaType<
    'static,
> = 0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeIntegerDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeLongDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeIntDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeShortDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeByteDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeUnsignedLongDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeUnsignedIntDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeUnsignedShortDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeUnsignedByteDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeNormStringDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeTokenDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeLanguageDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeNameDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeQNameDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeNCNameDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeIdDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeIdrefDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeIdrefsDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeEntityDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeEntitiesDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeNotationDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeNmtokenDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
static mut xmlSchemaTypeNmtokensDef: *mut crate::src::xmlschemas::_xmlSchemaType<'static> =
    0 as *const xmlSchemaType as xmlSchemaTypePtr;
extern "C" fn xmlSchemaTypeErrMemory(
    mut node: *mut crate::src::threads::_xmlNode,
    mut extra: *const i8,
) {
    (unsafe {
        __xmlSimpleError(
            XML_FROM_DATATYPE as i32,
            XML_ERR_NO_MEMORY as i32,
            node,
            0 as *const i8,
            extra,
        )
    });
}
extern "C" fn xmlSchemaNewValue(
    mut type_0: u32,
) -> *mut crate::src::xmlschemastypes::_xmlSchemaVal {
    let mut value: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    value = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlSchemaVal>() as u64)
    }) as xmlSchemaValPtr;
    if value.is_null() {
        return 0 as xmlSchemaValPtr;
    }
    (unsafe {
        memset(
            value as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlSchemaVal>() as u64,
        )
    });
    (unsafe { (*value).type_0 = type_0 });
    return value;
}
extern "C" fn xmlSchemaNewMinLengthFacet<'a1>(
    mut value: i32,
) -> *mut crate::src::xmlschemas::_xmlSchemaFacet<'a1> {
    let mut ret: *mut crate::src::xmlschemas::_xmlSchemaFacet<'_> = 0 as *mut xmlSchemaFacet;
    ret = xmlSchemaNewFacet();
    if ret.is_null() {
        return 0 as xmlSchemaFacetPtr;
    }
    (unsafe { (*ret).type_0 = XML_SCHEMA_FACET_MINLENGTH });
    let fresh0 = unsafe { &mut ((*ret).val) };
    *fresh0 = xmlSchemaNewValue(XML_SCHEMAS_NNINTEGER);
    if (unsafe { (*ret).val }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
        return 0 as xmlSchemaFacetPtr;
    }
    (unsafe { (*(*ret).val).value.decimal.lo = value as u64 });
    return ret;
}
extern "C" fn xmlSchemaInitBasicType<'a1, 'a2>(
    mut name: *const i8,
    mut type_0: u32,
    mut baseType: *mut crate::src::xmlschemas::_xmlSchemaType<'a1>,
) -> *mut crate::src::xmlschemas::_xmlSchemaType<'a2>
where
    'a1: 'a2,
    'a2: 'a1,
{
    let mut ret: *mut crate::src::xmlschemas::_xmlSchemaType<'_> = 0 as *mut xmlSchemaType;
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlSchemaType>() as u64)
    }) as xmlSchemaTypePtr;
    if ret.is_null() {
        xmlSchemaTypeErrMemory(
            0 as xmlNodePtr,
            b"could not initialize basic types\0" as *const u8 as *const i8,
        );
        return 0 as xmlSchemaTypePtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlSchemaType>() as u64,
        )
    });
    let fresh1 = unsafe { &mut ((*ret).name) };
    *fresh1 = name as *const xmlChar;
    let fresh2 = unsafe { &mut ((*ret).targetNamespace) };
    *fresh2 = b"http://www.w3.org/2001/XMLSchema\0" as *const u8 as *const i8 as *const xmlChar;
    (unsafe { (*ret).type_0 = XML_SCHEMA_TYPE_BASIC });
    let fresh3 = unsafe { &mut ((*ret).baseType) };
    *fresh3 = baseType;
    (unsafe { (*ret).contentType = XML_SCHEMA_CONTENT_BASIC });
    match type_0 as u32 {
        1 | 3 | 10 | 11 | 4 | 8 | 9 | 6 | 7 | 5 | 12 | 13 | 14 | 15 | 29 | 43 | 44 | 21 | 28 => {
            (unsafe { (*ret).flags |= (1 as i32) << 14 as i32 });
        }
        _ => {}
    }
    match type_0 as u32 {
        45 | 46 => {}
        25 | 19 | 27 => {
            (unsafe { (*ret).flags |= (1 as i32) << 6 as i32 });
            let fresh4 = unsafe { &mut ((*ret).facets) };
            *fresh4 = xmlSchemaNewMinLengthFacet(1 as i32);
            (unsafe { (*ret).flags |= (1 as i32) << 27 as i32 });
        }
        _ => {
            (unsafe { (*ret).flags |= (1 as i32) << 8 as i32 });
        }
    }
    (unsafe {
        xmlHashAddEntry2(
            xmlSchemaTypesBank,
            (*ret).name,
            b"http://www.w3.org/2001/XMLSchema\0" as *const u8 as *const i8 as *const xmlChar,
            ret as *mut libc::c_void,
        )
    });
    (unsafe { (*ret).builtInType = type_0 as i32 });
    return ret;
}
extern "C" fn xmlSchemaAddParticle() -> *mut crate::src::xmlschemas::_xmlSchemaParticle {
    let mut ret: *mut crate::src::xmlschemas::_xmlSchemaParticle = 0 as xmlSchemaParticlePtr;
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlSchemaParticle>() as u64
        )
    }) as xmlSchemaParticlePtr;
    if ret.is_null() {
        xmlSchemaTypeErrMemory(
            0 as xmlNodePtr,
            b"allocating particle component\0" as *const u8 as *const i8,
        );
        return 0 as xmlSchemaParticlePtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlSchemaParticle>() as u64,
        )
    });
    (unsafe { (*ret).type_0 = XML_SCHEMA_TYPE_PARTICLE });
    (unsafe { (*ret).minOccurs = 1 as i32 });
    (unsafe { (*ret).maxOccurs = 1 as i32 });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSchemaInitTypes() {
    if (unsafe { xmlSchemaTypesInitialized }) != 0 as i32 {
        return;
    }
    (unsafe { xmlSchemaTypesBank = xmlHashCreate(40 as i32) });
    (unsafe {
        xmlSchemaTypeAnyTypeDef = xmlSchemaInitBasicType(
            b"anyType\0" as *const u8 as *const i8,
            XML_SCHEMAS_ANYTYPE,
            0 as xmlSchemaTypePtr,
        )
    });
    let fresh5 = unsafe { &mut ((*xmlSchemaTypeAnyTypeDef).baseType) };
    *fresh5 = unsafe { xmlSchemaTypeAnyTypeDef };
    (unsafe { (*xmlSchemaTypeAnyTypeDef).contentType = XML_SCHEMA_CONTENT_MIXED });
    (unsafe { (*xmlSchemaTypeAnyTypeDef).contentType = XML_SCHEMA_CONTENT_MIXED });
    let mut particle: *mut crate::src::xmlschemas::_xmlSchemaParticle = 0 as *mut xmlSchemaParticle;
    let mut sequence: *mut crate::src::xmlschemas::_xmlSchemaModelGroup<'_> =
        0 as *mut xmlSchemaModelGroup;
    let mut wild: *mut crate::src::xmlschemas::_xmlSchemaWildcard<'_> = 0 as *mut xmlSchemaWildcard;
    particle = xmlSchemaAddParticle();
    if particle.is_null() {
        return;
    }
    let fresh6 = unsafe { &mut ((*xmlSchemaTypeAnyTypeDef).subtypes) };
    *fresh6 = particle as xmlSchemaTypePtr;
    sequence = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlSchemaModelGroup>() as u64
        )
    }) as xmlSchemaModelGroupPtr;
    if sequence.is_null() {
        xmlSchemaTypeErrMemory(
            0 as xmlNodePtr,
            b"allocating model group component\0" as *const u8 as *const i8,
        );
        return;
    }
    (unsafe {
        memset(
            sequence as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlSchemaModelGroup>() as u64,
        )
    });
    (unsafe { (*sequence).type_0 = XML_SCHEMA_TYPE_SEQUENCE });
    let fresh7 = unsafe { &mut ((*particle).children) };
    *fresh7 = sequence as xmlSchemaTreeItemPtr;
    particle = xmlSchemaAddParticle();
    if particle.is_null() {
        return;
    }
    (unsafe { (*particle).minOccurs = 0 as i32 });
    (unsafe { (*particle).maxOccurs = (1 as i32) << 30 as i32 });
    let fresh8 = unsafe { &mut ((*sequence).children) };
    *fresh8 = particle as xmlSchemaTreeItemPtr;
    wild = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlSchemaWildcard>() as u64
        )
    }) as xmlSchemaWildcardPtr;
    if wild.is_null() {
        xmlSchemaTypeErrMemory(
            0 as xmlNodePtr,
            b"allocating wildcard component\0" as *const u8 as *const i8,
        );
        return;
    }
    (unsafe {
        memset(
            wild as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlSchemaWildcard>() as u64,
        )
    });
    (unsafe { (*wild).type_0 = XML_SCHEMA_TYPE_ANY });
    (unsafe { (*wild).any = 1 as i32 });
    (unsafe { (*wild).processContents = 2 as i32 });
    let fresh9 = unsafe { &mut ((*particle).children) };
    *fresh9 = wild as xmlSchemaTreeItemPtr;
    wild = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlSchemaWildcard>() as u64
        )
    }) as xmlSchemaWildcardPtr;
    if wild.is_null() {
        xmlSchemaTypeErrMemory(
            0 as xmlNodePtr,
            b"could not create an attribute wildcard on anyType\0" as *const u8 as *const i8,
        );
        return;
    }
    (unsafe {
        memset(
            wild as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlSchemaWildcard>() as u64,
        )
    });
    (unsafe { (*wild).any = 1 as i32 });
    (unsafe { (*wild).processContents = 2 as i32 });
    let fresh10 = unsafe { &mut ((*xmlSchemaTypeAnyTypeDef).attributeWildcard) };
    *fresh10 = wild;
    (unsafe {
        xmlSchemaTypeAnySimpleTypeDef = xmlSchemaInitBasicType(
            b"anySimpleType\0" as *const u8 as *const i8,
            XML_SCHEMAS_ANYSIMPLETYPE,
            xmlSchemaTypeAnyTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeStringDef = xmlSchemaInitBasicType(
            b"string\0" as *const u8 as *const i8,
            XML_SCHEMAS_STRING,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeDecimalDef = xmlSchemaInitBasicType(
            b"decimal\0" as *const u8 as *const i8,
            XML_SCHEMAS_DECIMAL,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeDateDef = xmlSchemaInitBasicType(
            b"date\0" as *const u8 as *const i8,
            XML_SCHEMAS_DATE,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeDatetimeDef = xmlSchemaInitBasicType(
            b"dateTime\0" as *const u8 as *const i8,
            XML_SCHEMAS_DATETIME,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeTimeDef = xmlSchemaInitBasicType(
            b"time\0" as *const u8 as *const i8,
            XML_SCHEMAS_TIME,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeGYearDef = xmlSchemaInitBasicType(
            b"gYear\0" as *const u8 as *const i8,
            XML_SCHEMAS_GYEAR,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeGYearMonthDef = xmlSchemaInitBasicType(
            b"gYearMonth\0" as *const u8 as *const i8,
            XML_SCHEMAS_GYEARMONTH,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeGMonthDef = xmlSchemaInitBasicType(
            b"gMonth\0" as *const u8 as *const i8,
            XML_SCHEMAS_GMONTH,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeGMonthDayDef = xmlSchemaInitBasicType(
            b"gMonthDay\0" as *const u8 as *const i8,
            XML_SCHEMAS_GMONTHDAY,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeGDayDef = xmlSchemaInitBasicType(
            b"gDay\0" as *const u8 as *const i8,
            XML_SCHEMAS_GDAY,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeDurationDef = xmlSchemaInitBasicType(
            b"duration\0" as *const u8 as *const i8,
            XML_SCHEMAS_DURATION,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeFloatDef = xmlSchemaInitBasicType(
            b"float\0" as *const u8 as *const i8,
            XML_SCHEMAS_FLOAT,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeDoubleDef = xmlSchemaInitBasicType(
            b"double\0" as *const u8 as *const i8,
            XML_SCHEMAS_DOUBLE,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeBooleanDef = xmlSchemaInitBasicType(
            b"boolean\0" as *const u8 as *const i8,
            XML_SCHEMAS_BOOLEAN,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeAnyURIDef = xmlSchemaInitBasicType(
            b"anyURI\0" as *const u8 as *const i8,
            XML_SCHEMAS_ANYURI,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeHexBinaryDef = xmlSchemaInitBasicType(
            b"hexBinary\0" as *const u8 as *const i8,
            XML_SCHEMAS_HEXBINARY,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeBase64BinaryDef = xmlSchemaInitBasicType(
            b"base64Binary\0" as *const u8 as *const i8,
            XML_SCHEMAS_BASE64BINARY,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeNotationDef = xmlSchemaInitBasicType(
            b"NOTATION\0" as *const u8 as *const i8,
            XML_SCHEMAS_NOTATION,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeQNameDef = xmlSchemaInitBasicType(
            b"QName\0" as *const u8 as *const i8,
            XML_SCHEMAS_QNAME,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    (unsafe {
        xmlSchemaTypeIntegerDef = xmlSchemaInitBasicType(
            b"integer\0" as *const u8 as *const i8,
            XML_SCHEMAS_INTEGER,
            xmlSchemaTypeDecimalDef,
        )
    });
    (unsafe {
        xmlSchemaTypeNonPositiveIntegerDef = xmlSchemaInitBasicType(
            b"nonPositiveInteger\0" as *const u8 as *const i8,
            XML_SCHEMAS_NPINTEGER,
            xmlSchemaTypeIntegerDef,
        )
    });
    (unsafe {
        xmlSchemaTypeNegativeIntegerDef = xmlSchemaInitBasicType(
            b"negativeInteger\0" as *const u8 as *const i8,
            XML_SCHEMAS_NINTEGER,
            xmlSchemaTypeNonPositiveIntegerDef,
        )
    });
    (unsafe {
        xmlSchemaTypeLongDef = xmlSchemaInitBasicType(
            b"long\0" as *const u8 as *const i8,
            XML_SCHEMAS_LONG,
            xmlSchemaTypeIntegerDef,
        )
    });
    (unsafe {
        xmlSchemaTypeIntDef = xmlSchemaInitBasicType(
            b"int\0" as *const u8 as *const i8,
            XML_SCHEMAS_INT,
            xmlSchemaTypeLongDef,
        )
    });
    (unsafe {
        xmlSchemaTypeShortDef = xmlSchemaInitBasicType(
            b"short\0" as *const u8 as *const i8,
            XML_SCHEMAS_SHORT,
            xmlSchemaTypeIntDef,
        )
    });
    (unsafe {
        xmlSchemaTypeByteDef = xmlSchemaInitBasicType(
            b"byte\0" as *const u8 as *const i8,
            XML_SCHEMAS_BYTE,
            xmlSchemaTypeShortDef,
        )
    });
    (unsafe {
        xmlSchemaTypeNonNegativeIntegerDef = xmlSchemaInitBasicType(
            b"nonNegativeInteger\0" as *const u8 as *const i8,
            XML_SCHEMAS_NNINTEGER,
            xmlSchemaTypeIntegerDef,
        )
    });
    (unsafe {
        xmlSchemaTypeUnsignedLongDef = xmlSchemaInitBasicType(
            b"unsignedLong\0" as *const u8 as *const i8,
            XML_SCHEMAS_ULONG,
            xmlSchemaTypeNonNegativeIntegerDef,
        )
    });
    (unsafe {
        xmlSchemaTypeUnsignedIntDef = xmlSchemaInitBasicType(
            b"unsignedInt\0" as *const u8 as *const i8,
            XML_SCHEMAS_UINT,
            xmlSchemaTypeUnsignedLongDef,
        )
    });
    (unsafe {
        xmlSchemaTypeUnsignedShortDef = xmlSchemaInitBasicType(
            b"unsignedShort\0" as *const u8 as *const i8,
            XML_SCHEMAS_USHORT,
            xmlSchemaTypeUnsignedIntDef,
        )
    });
    (unsafe {
        xmlSchemaTypeUnsignedByteDef = xmlSchemaInitBasicType(
            b"unsignedByte\0" as *const u8 as *const i8,
            XML_SCHEMAS_UBYTE,
            xmlSchemaTypeUnsignedShortDef,
        )
    });
    (unsafe {
        xmlSchemaTypePositiveIntegerDef = xmlSchemaInitBasicType(
            b"positiveInteger\0" as *const u8 as *const i8,
            XML_SCHEMAS_PINTEGER,
            xmlSchemaTypeNonNegativeIntegerDef,
        )
    });
    (unsafe {
        xmlSchemaTypeNormStringDef = xmlSchemaInitBasicType(
            b"normalizedString\0" as *const u8 as *const i8,
            XML_SCHEMAS_NORMSTRING,
            xmlSchemaTypeStringDef,
        )
    });
    (unsafe {
        xmlSchemaTypeTokenDef = xmlSchemaInitBasicType(
            b"token\0" as *const u8 as *const i8,
            XML_SCHEMAS_TOKEN,
            xmlSchemaTypeNormStringDef,
        )
    });
    (unsafe {
        xmlSchemaTypeLanguageDef = xmlSchemaInitBasicType(
            b"language\0" as *const u8 as *const i8,
            XML_SCHEMAS_LANGUAGE,
            xmlSchemaTypeTokenDef,
        )
    });
    (unsafe {
        xmlSchemaTypeNameDef = xmlSchemaInitBasicType(
            b"Name\0" as *const u8 as *const i8,
            XML_SCHEMAS_NAME,
            xmlSchemaTypeTokenDef,
        )
    });
    (unsafe {
        xmlSchemaTypeNmtokenDef = xmlSchemaInitBasicType(
            b"NMTOKEN\0" as *const u8 as *const i8,
            XML_SCHEMAS_NMTOKEN,
            xmlSchemaTypeTokenDef,
        )
    });
    (unsafe {
        xmlSchemaTypeNCNameDef = xmlSchemaInitBasicType(
            b"NCName\0" as *const u8 as *const i8,
            XML_SCHEMAS_NCNAME,
            xmlSchemaTypeNameDef,
        )
    });
    (unsafe {
        xmlSchemaTypeIdDef = xmlSchemaInitBasicType(
            b"ID\0" as *const u8 as *const i8,
            XML_SCHEMAS_ID,
            xmlSchemaTypeNCNameDef,
        )
    });
    (unsafe {
        xmlSchemaTypeIdrefDef = xmlSchemaInitBasicType(
            b"IDREF\0" as *const u8 as *const i8,
            XML_SCHEMAS_IDREF,
            xmlSchemaTypeNCNameDef,
        )
    });
    (unsafe {
        xmlSchemaTypeEntityDef = xmlSchemaInitBasicType(
            b"ENTITY\0" as *const u8 as *const i8,
            XML_SCHEMAS_ENTITY,
            xmlSchemaTypeNCNameDef,
        )
    });
    (unsafe {
        xmlSchemaTypeEntitiesDef = xmlSchemaInitBasicType(
            b"ENTITIES\0" as *const u8 as *const i8,
            XML_SCHEMAS_ENTITIES,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    let fresh11 = unsafe { &mut ((*xmlSchemaTypeEntitiesDef).subtypes) };
    *fresh11 = unsafe { xmlSchemaTypeEntityDef };
    (unsafe {
        xmlSchemaTypeIdrefsDef = xmlSchemaInitBasicType(
            b"IDREFS\0" as *const u8 as *const i8,
            XML_SCHEMAS_IDREFS,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    let fresh12 = unsafe { &mut ((*xmlSchemaTypeIdrefsDef).subtypes) };
    *fresh12 = unsafe { xmlSchemaTypeIdrefDef };
    (unsafe {
        xmlSchemaTypeNmtokensDef = xmlSchemaInitBasicType(
            b"NMTOKENS\0" as *const u8 as *const i8,
            XML_SCHEMAS_NMTOKENS,
            xmlSchemaTypeAnySimpleTypeDef,
        )
    });
    let fresh13 = unsafe { &mut ((*xmlSchemaTypeNmtokensDef).subtypes) };
    *fresh13 = unsafe { xmlSchemaTypeNmtokenDef };
    (unsafe { xmlSchemaTypesInitialized = 1 as i32 });
}
extern "C" fn xmlSchemaFreeTypeEntry(mut type_0: *mut core::ffi::c_void, mut _name: *const u8) {
    xmlSchemaFreeType(type_0 as xmlSchemaTypePtr);
}
#[no_mangle]
pub extern "C" fn xmlSchemaCleanupTypes() {
    if (unsafe { xmlSchemaTypesInitialized }) == 0 as i32 {
        return;
    }
    let mut particle: *mut crate::src::xmlschemas::_xmlSchemaParticle = 0 as *mut xmlSchemaParticle;
    xmlSchemaFreeWildcard(unsafe { (*xmlSchemaTypeAnyTypeDef).attributeWildcard });
    particle = (unsafe { (*xmlSchemaTypeAnyTypeDef).subtypes }) as xmlSchemaParticlePtr;
    xmlSchemaFreeWildcard(
        (unsafe { (*(*(*particle).children).children).children }) as xmlSchemaWildcardPtr,
    );
    (unsafe {
        xmlFree.expect("non-null function pointer")(
            (*(*particle).children).children as xmlSchemaParticlePtr as *mut libc::c_void,
        )
    });
    (unsafe {
        xmlFree.expect("non-null function pointer")(
            (*particle).children as xmlSchemaModelGroupPtr as *mut libc::c_void,
        )
    });
    (unsafe { xmlFree.expect("non-null function pointer")(particle as *mut libc::c_void) });
    let fresh14 = unsafe { &mut ((*xmlSchemaTypeAnyTypeDef).subtypes) };
    *fresh14 = 0 as xmlSchemaTypePtr;
    (unsafe { xmlHashFree(xmlSchemaTypesBank, Some(xmlSchemaFreeTypeEntry)) });
    (unsafe { xmlSchemaTypesInitialized = 0 as i32 });
}
#[no_mangle]
pub extern "C" fn xmlSchemaIsBuiltInTypeFacet<'a1>(
    mut type_0: *mut crate::src::xmlschemas::_xmlSchemaType<'a1>,
    mut facetType: i32,
) -> i32 {
    if type_0.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*type_0).type_0 }) as u32 != XML_SCHEMA_TYPE_BASIC as i32 as u32 {
        return -(1 as i32);
    }
    match unsafe { (*type_0).builtInType } {
        15 => {
            if facetType == XML_SCHEMA_FACET_PATTERN as i32
                || facetType == XML_SCHEMA_FACET_WHITESPACE as i32
            {
                return 1 as i32;
            } else {
                return 0 as i32;
            }
        }
        1 | 28 | 21 | 29 | 44 | 43 => {
            if facetType == XML_SCHEMA_FACET_LENGTH as i32
                || facetType == XML_SCHEMA_FACET_MINLENGTH as i32
                || facetType == XML_SCHEMA_FACET_MAXLENGTH as i32
                || facetType == XML_SCHEMA_FACET_PATTERN as i32
                || facetType == XML_SCHEMA_FACET_ENUMERATION as i32
                || facetType == XML_SCHEMA_FACET_WHITESPACE as i32
            {
                return 1 as i32;
            } else {
                return 0 as i32;
            }
        }
        3 => {
            if facetType == XML_SCHEMA_FACET_TOTALDIGITS as i32
                || facetType == XML_SCHEMA_FACET_FRACTIONDIGITS as i32
                || facetType == XML_SCHEMA_FACET_PATTERN as i32
                || facetType == XML_SCHEMA_FACET_WHITESPACE as i32
                || facetType == XML_SCHEMA_FACET_ENUMERATION as i32
                || facetType == XML_SCHEMA_FACET_MAXINCLUSIVE as i32
                || facetType == XML_SCHEMA_FACET_MAXEXCLUSIVE as i32
                || facetType == XML_SCHEMA_FACET_MININCLUSIVE as i32
                || facetType == XML_SCHEMA_FACET_MINEXCLUSIVE as i32
            {
                return 1 as i32;
            } else {
                return 0 as i32;
            }
        }
        4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 => {
            if facetType == XML_SCHEMA_FACET_PATTERN as i32
                || facetType == XML_SCHEMA_FACET_ENUMERATION as i32
                || facetType == XML_SCHEMA_FACET_WHITESPACE as i32
                || facetType == XML_SCHEMA_FACET_MAXINCLUSIVE as i32
                || facetType == XML_SCHEMA_FACET_MAXEXCLUSIVE as i32
                || facetType == XML_SCHEMA_FACET_MININCLUSIVE as i32
                || facetType == XML_SCHEMA_FACET_MINEXCLUSIVE as i32
            {
                return 1 as i32;
            } else {
                return 0 as i32;
            }
        }
        _ => {}
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlSchemaGetBuiltInType<'a1>(
    mut type_0: u32,
) -> *mut crate::src::xmlschemas::_xmlSchemaType<'a1>
where
    'a1: 'static,
{
    if (unsafe { xmlSchemaTypesInitialized }) == 0 as i32 {
        xmlSchemaInitTypes();
    }
    match type_0 as u32 {
        46 => return unsafe { xmlSchemaTypeAnySimpleTypeDef },
        1 => return unsafe { xmlSchemaTypeStringDef },
        2 => return unsafe { xmlSchemaTypeNormStringDef },
        3 => return unsafe { xmlSchemaTypeDecimalDef },
        4 => return unsafe { xmlSchemaTypeTimeDef },
        5 => return unsafe { xmlSchemaTypeGDayDef },
        6 => return unsafe { xmlSchemaTypeGMonthDef },
        7 => return unsafe { xmlSchemaTypeGMonthDayDef },
        8 => return unsafe { xmlSchemaTypeGYearDef },
        9 => return unsafe { xmlSchemaTypeGYearMonthDef },
        10 => return unsafe { xmlSchemaTypeDateDef },
        11 => return unsafe { xmlSchemaTypeDatetimeDef },
        12 => return unsafe { xmlSchemaTypeDurationDef },
        13 => return unsafe { xmlSchemaTypeFloatDef },
        14 => return unsafe { xmlSchemaTypeDoubleDef },
        15 => return unsafe { xmlSchemaTypeBooleanDef },
        16 => return unsafe { xmlSchemaTypeTokenDef },
        17 => return unsafe { xmlSchemaTypeLanguageDef },
        18 => return unsafe { xmlSchemaTypeNmtokenDef },
        19 => return unsafe { xmlSchemaTypeNmtokensDef },
        20 => return unsafe { xmlSchemaTypeNameDef },
        21 => return unsafe { xmlSchemaTypeQNameDef },
        22 => return unsafe { xmlSchemaTypeNCNameDef },
        23 => return unsafe { xmlSchemaTypeIdDef },
        24 => return unsafe { xmlSchemaTypeIdrefDef },
        25 => return unsafe { xmlSchemaTypeIdrefsDef },
        26 => return unsafe { xmlSchemaTypeEntityDef },
        27 => return unsafe { xmlSchemaTypeEntitiesDef },
        28 => return unsafe { xmlSchemaTypeNotationDef },
        29 => return unsafe { xmlSchemaTypeAnyURIDef },
        30 => return unsafe { xmlSchemaTypeIntegerDef },
        31 => return unsafe { xmlSchemaTypeNonPositiveIntegerDef },
        32 => return unsafe { xmlSchemaTypeNegativeIntegerDef },
        33 => return unsafe { xmlSchemaTypeNonNegativeIntegerDef },
        34 => return unsafe { xmlSchemaTypePositiveIntegerDef },
        35 => return unsafe { xmlSchemaTypeIntDef },
        36 => return unsafe { xmlSchemaTypeUnsignedIntDef },
        37 => return unsafe { xmlSchemaTypeLongDef },
        38 => return unsafe { xmlSchemaTypeUnsignedLongDef },
        39 => return unsafe { xmlSchemaTypeShortDef },
        40 => return unsafe { xmlSchemaTypeUnsignedShortDef },
        41 => return unsafe { xmlSchemaTypeByteDef },
        42 => return unsafe { xmlSchemaTypeUnsignedByteDef },
        43 => return unsafe { xmlSchemaTypeHexBinaryDef },
        44 => return unsafe { xmlSchemaTypeBase64BinaryDef },
        45 => return unsafe { xmlSchemaTypeAnyTypeDef },
        _ => return 0 as xmlSchemaTypePtr,
    };
}
#[no_mangle]
pub extern "C" fn xmlSchemaValueAppend(
    mut prev: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut cur: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> i32 {
    if prev.is_null() || cur.is_null() {
        return -(1 as i32);
    }
    let fresh15 = unsafe { &mut ((*prev).next) };
    *fresh15 = cur;
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlSchemaValueGetNext(
    mut cur: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> *mut crate::src::xmlschemastypes::_xmlSchemaVal {
    if cur.is_null() {
        return 0 as xmlSchemaValPtr;
    }
    return unsafe { (*cur).next };
}
#[no_mangle]
pub extern "C" fn xmlSchemaValueGetAsString(
    mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> *const u8 {
    if val.is_null() {
        return 0 as *const xmlChar;
    }
    match (unsafe { (*val).type_0 }) as u32 {
        1 | 2 | 46 | 16 | 17 | 18 | 20 | 22 | 23 | 24 | 26 | 29 => {
            return unsafe { (*val).value.str_0 };
        }
        _ => {}
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlSchemaValueGetAsBoolean(
    mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> i32 {
    if val.is_null() || (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_BOOLEAN as i32 as u32 {
        return 0 as i32;
    }
    return unsafe { (*val).value.b };
}
#[no_mangle]
pub extern "C" fn xmlSchemaNewStringValue(
    mut type_0: u32,
    mut value: *const u8,
) -> *mut crate::src::xmlschemastypes::_xmlSchemaVal {
    let mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    if type_0 as u32 != XML_SCHEMAS_STRING as i32 as u32 {
        return 0 as xmlSchemaValPtr;
    }
    val = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlSchemaVal>() as u64)
    }) as xmlSchemaValPtr;
    if val.is_null() {
        return 0 as xmlSchemaValPtr;
    }
    (unsafe {
        memset(
            val as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlSchemaVal>() as u64,
        )
    });
    (unsafe { (*val).type_0 = type_0 });
    let fresh16 = unsafe { &mut ((*val).value.str_0) };
    *fresh16 = value as *mut xmlChar;
    return val;
}
#[no_mangle]
pub extern "C" fn xmlSchemaNewNOTATIONValue(
    mut name: *const u8,
    mut ns: *const u8,
) -> *mut crate::src::xmlschemastypes::_xmlSchemaVal {
    let mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    val = xmlSchemaNewValue(XML_SCHEMAS_NOTATION);
    if val.is_null() {
        return 0 as xmlSchemaValPtr;
    }
    let fresh17 = unsafe { &mut ((*val).value.qname.name) };
    *fresh17 = name as *mut xmlChar;
    if !ns.is_null() {
        let fresh18 = unsafe { &mut ((*val).value.qname.uri) };
        *fresh18 = ns as *mut xmlChar;
    }
    return val;
}
#[no_mangle]
pub extern "C" fn xmlSchemaNewQNameValue(
    mut namespaceName: *const u8,
    mut localName: *const u8,
) -> *mut crate::src::xmlschemastypes::_xmlSchemaVal {
    let mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    val = xmlSchemaNewValue(XML_SCHEMAS_QNAME);
    if val.is_null() {
        return 0 as xmlSchemaValPtr;
    }
    let fresh19 = unsafe { &mut ((*val).value.qname.name) };
    *fresh19 = localName as *mut xmlChar;
    let fresh20 = unsafe { &mut ((*val).value.qname.uri) };
    *fresh20 = namespaceName as *mut xmlChar;
    return val;
}
#[no_mangle]
pub extern "C" fn xmlSchemaFreeValue(mut value: *mut crate::src::xmlschemastypes::_xmlSchemaVal) {
    let mut prev: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    while !value.is_null() {
        match (unsafe { (*value).type_0 }) as u32 {
            1 | 2 | 16 | 17 | 18 | 19 | 20 | 22 | 23 | 24 | 25 | 26 | 27 | 29 | 46 => {
                if !(unsafe { (*value).value.str_0 }).is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(
                            (*value).value.str_0 as *mut libc::c_void,
                        )
                    });
                }
            }
            28 | 21 => {
                if !(unsafe { (*value).value.qname.uri }).is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(
                            (*value).value.qname.uri as *mut libc::c_void,
                        )
                    });
                }
                if !(unsafe { (*value).value.qname.name }).is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(
                            (*value).value.qname.name as *mut libc::c_void,
                        )
                    });
                }
            }
            43 => {
                if !(unsafe { (*value).value.hex.str_0 }).is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(
                            (*value).value.hex.str_0 as *mut libc::c_void,
                        )
                    });
                }
            }
            44 => {
                if !(unsafe { (*value).value.base64.str_0 }).is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(
                            (*value).value.base64.str_0 as *mut libc::c_void,
                        )
                    });
                }
            }
            _ => {}
        }
        prev = value;
        value = unsafe { (*value).next };
        (unsafe { xmlFree.expect("non-null function pointer")(prev as *mut libc::c_void) });
    }
}
#[no_mangle]
pub extern "C" fn xmlSchemaGetPredefinedType<'a1>(
    mut name: *const u8,
    mut ns: *const u8,
) -> *mut crate::src::xmlschemas::_xmlSchemaType<'a1> {
    if (unsafe { xmlSchemaTypesInitialized }) == 0 as i32 {
        xmlSchemaInitTypes();
    }
    if name.is_null() {
        return 0 as xmlSchemaTypePtr;
    }
    return (unsafe { xmlHashLookup2(xmlSchemaTypesBank, name, ns) }) as xmlSchemaTypePtr;
}
#[no_mangle]
pub extern "C" fn xmlSchemaGetBuiltInListSimpleTypeItemType<'a1, 'a2, 'a3>(
    mut type_0: Option<&'a1 mut crate::src::xmlschemas::_xmlSchemaType<'a2>>,
) -> *mut crate::src::xmlschemas::_xmlSchemaType<'a3>
where
    'a3: 'static,
{
    if borrow(&type_0).is_none()
        || (*(borrow(&type_0)).unwrap()).type_0 as u32 != XML_SCHEMA_TYPE_BASIC as i32 as u32
    {
        return 0 as xmlSchemaTypePtr;
    }
    match (*(borrow(&type_0)).unwrap()).builtInType {
        19 => return unsafe { xmlSchemaTypeNmtokenDef },
        25 => return unsafe { xmlSchemaTypeIdrefDef },
        27 => return unsafe { xmlSchemaTypeEntityDef },
        _ => return 0 as xmlSchemaTypePtr,
    };
}
static mut daysInMonth: [u32; 12] = [
    31 as i32 as u32,
    28 as i32 as u32,
    31 as i32 as u32,
    30 as i32 as u32,
    31 as i32 as u32,
    30 as i32 as u32,
    31 as i32 as u32,
    31 as i32 as u32,
    30 as i32 as u32,
    31 as i32 as u32,
    30 as i32 as u32,
    31 as i32 as u32,
];
static mut daysInMonthLeap: [u32; 12] = [
    31 as i32 as u32,
    29 as i32 as u32,
    31 as i32 as u32,
    30 as i32 as u32,
    31 as i32 as u32,
    30 as i32 as u32,
    31 as i32 as u32,
    31 as i32 as u32,
    30 as i32 as u32,
    31 as i32 as u32,
    30 as i32 as u32,
    31 as i32 as u32,
];
static mut dayInYearByMonth: [i64; 12] = [
    0 as i32 as i64,
    31 as i32 as i64,
    59 as i32 as i64,
    90 as i32 as i64,
    120 as i32 as i64,
    151 as i32 as i64,
    181 as i32 as i64,
    212 as i32 as i64,
    243 as i32 as i64,
    273 as i32 as i64,
    304 as i32 as i64,
    334 as i32 as i64,
];
static mut dayInLeapYearByMonth: [i64; 12] = [
    0 as i32 as i64,
    31 as i32 as i64,
    60 as i32 as i64,
    91 as i32 as i64,
    121 as i32 as i64,
    152 as i32 as i64,
    182 as i32 as i64,
    213 as i32 as i64,
    244 as i32 as i64,
    274 as i32 as i64,
    305 as i32 as i64,
    335 as i32 as i64,
];
extern "C" fn _xmlSchemaParseGYear<'a1, 'a2>(
    mut dt: Option<&'a1 mut crate::src::xmlschemastypes::_xmlSchemaValDate>,
    mut str: Option<&'a2 mut *const u8>,
) -> i32 {
    let mut cur: *const u8 = *(borrow(&str)).unwrap();
    let mut firstChar: *const u8 = 0 as *const xmlChar;
    let mut isneg: i32 = 0 as i32;
    let mut digcnt: i32 = 0 as i32;
    if (((unsafe { *cur }) as i32) < '0' as i32 || (unsafe { *cur }) as i32 > '9' as i32)
        && (unsafe { *cur }) as i32 != '-' as i32
        && (unsafe { *cur }) as i32 != '+' as i32
    {
        return -(1 as i32);
    }
    if (unsafe { *cur }) as i32 == '-' as i32 {
        isneg = 1 as i32;
        cur = unsafe { cur.offset(1) };
    }
    firstChar = cur;
    while (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
        let mut digit: i32 = (unsafe { *cur }) as i32 - '0' as i32;
        if (*(borrow(&dt)).unwrap()).year > 9223372036854775807 as i64 / 10 as i32 as i64 {
            return 2 as i32;
        }
        (*(borrow_mut(&mut dt)).unwrap()).year *= 10 as i32 as i64;
        if (*(borrow(&dt)).unwrap()).year > 9223372036854775807 as i64 - digit as i64 {
            return 2 as i32;
        }
        (*(borrow_mut(&mut dt)).unwrap()).year += digit as i64;
        cur = unsafe { cur.offset(1) };
        digcnt += 1;
    }
    if digcnt < 4 as i32 || digcnt > 4 as i32 && (unsafe { *firstChar }) as i32 == '0' as i32 {
        return 1 as i32;
    }
    if isneg != 0 {
        (*(borrow_mut(&mut dt)).unwrap()).year = -(*(borrow(&dt)).unwrap()).year;
    }
    if !((*(borrow(&dt)).unwrap()).year != 0 as i32 as i64) {
        return 2 as i32;
    }
    *(borrow_mut(&mut str)).unwrap() = cur;
    return 0 as i32;
}
extern "C" fn _xmlSchemaParseGMonth<'a1, 'a2>(
    mut dt: Option<&'a1 mut crate::src::xmlschemastypes::_xmlSchemaValDate>,
    mut str: Option<&'a2 mut *const u8>,
) -> i32 {
    let mut cur: *const u8 = *(borrow(&str)).unwrap();
    let mut ret: i32 = 0 as i32;
    let mut value: u32 = 0 as i32 as u32;
    if ((unsafe { *cur.offset(0 as i32 as isize) }) as i32) < '0' as i32
        || (unsafe { *cur.offset(0 as i32 as isize) }) as i32 > '9' as i32
        || ((unsafe { *cur.offset(1 as i32 as isize) }) as i32) < '0' as i32
        || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 > '9' as i32
    {
        ret = 1 as i32;
    } else {
        value = (((unsafe { *cur.offset(0 as i32 as isize) }) as i32 - '0' as i32) * 10 as i32
            + ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 - '0' as i32))
            as u32;
    }
    cur = unsafe { cur.offset(2 as i32 as isize) };
    if ret != 0 as i32 {
        return ret;
    }
    if !(value >= 1 as i32 as u32 && value <= 12 as i32 as u32) {
        return 2 as i32;
    }
    (*(borrow_mut(&mut dt)).unwrap()).set_mon(value);
    *(borrow_mut(&mut str)).unwrap() = cur;
    return 0 as i32;
}
extern "C" fn _xmlSchemaParseGDay<'a1, 'a2>(
    mut dt: Option<&'a1 mut crate::src::xmlschemastypes::_xmlSchemaValDate>,
    mut str: Option<&'a2 mut *const u8>,
) -> i32 {
    let mut cur: *const u8 = *(borrow(&str)).unwrap();
    let mut ret: i32 = 0 as i32;
    let mut value: u32 = 0 as i32 as u32;
    if ((unsafe { *cur.offset(0 as i32 as isize) }) as i32) < '0' as i32
        || (unsafe { *cur.offset(0 as i32 as isize) }) as i32 > '9' as i32
        || ((unsafe { *cur.offset(1 as i32 as isize) }) as i32) < '0' as i32
        || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 > '9' as i32
    {
        ret = 1 as i32;
    } else {
        value = (((unsafe { *cur.offset(0 as i32 as isize) }) as i32 - '0' as i32) * 10 as i32
            + ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 - '0' as i32))
            as u32;
    }
    cur = unsafe { cur.offset(2 as i32 as isize) };
    if ret != 0 as i32 {
        return ret;
    }
    if !(value >= 1 as i32 as u32 && value <= 31 as i32 as u32) {
        return 2 as i32;
    }
    (*(borrow_mut(&mut dt)).unwrap()).set_day(value);
    *(borrow_mut(&mut str)).unwrap() = cur;
    return 0 as i32;
}
extern "C" fn _xmlSchemaParseTime<'a1, 'a2>(
    mut dt: Option<&'a1 mut crate::src::xmlschemastypes::_xmlSchemaValDate>,
    mut str: Option<&'a2 mut *const u8>,
) -> i32 {
    let mut cur: *const u8 = *(borrow(&str)).unwrap();
    let mut ret: i32 = 0 as i32;
    let mut value: i32 = 0 as i32;
    if ((unsafe { *cur.offset(0 as i32 as isize) }) as i32) < '0' as i32
        || (unsafe { *cur.offset(0 as i32 as isize) }) as i32 > '9' as i32
        || ((unsafe { *cur.offset(1 as i32 as isize) }) as i32) < '0' as i32
        || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 > '9' as i32
    {
        ret = 1 as i32;
    } else {
        value = ((unsafe { *cur.offset(0 as i32 as isize) }) as i32 - '0' as i32) * 10 as i32
            + ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 - '0' as i32);
    }
    cur = unsafe { cur.offset(2 as i32 as isize) };
    if ret != 0 as i32 {
        return ret;
    }
    if (unsafe { *cur }) as i32 != ':' as i32 {
        return 1 as i32;
    }
    if !(value >= 0 as i32 && value <= 23 as i32) && value != 24 as i32 {
        return 2 as i32;
    }
    cur = unsafe { cur.offset(1) };
    (*(borrow_mut(&mut dt)).unwrap()).set_hour(value as u32);
    if ((unsafe { *cur.offset(0 as i32 as isize) }) as i32) < '0' as i32
        || (unsafe { *cur.offset(0 as i32 as isize) }) as i32 > '9' as i32
        || ((unsafe { *cur.offset(1 as i32 as isize) }) as i32) < '0' as i32
        || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 > '9' as i32
    {
        ret = 1 as i32;
    } else {
        value = ((unsafe { *cur.offset(0 as i32 as isize) }) as i32 - '0' as i32) * 10 as i32
            + ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 - '0' as i32);
    }
    cur = unsafe { cur.offset(2 as i32 as isize) };
    if ret != 0 as i32 {
        return ret;
    }
    if !(value >= 0 as i32 && value <= 59 as i32) {
        return 2 as i32;
    }
    (*(borrow_mut(&mut dt)).unwrap()).set_min(value as u32);
    if (unsafe { *cur }) as i32 != ':' as i32 {
        return 1 as i32;
    }
    cur = unsafe { cur.offset(1) };
    if ((unsafe { *cur.offset(0 as i32 as isize) }) as i32) < '0' as i32
        || (unsafe { *cur.offset(0 as i32 as isize) }) as i32 > '9' as i32
        || ((unsafe { *cur.offset(1 as i32 as isize) }) as i32) < '0' as i32
        || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 > '9' as i32
    {
        ret = 1 as i32;
    } else {
        (*(borrow_mut(&mut dt)).unwrap()).sec =
            (((unsafe { *cur.offset(0 as i32 as isize) }) as i32 - '0' as i32) * 10 as i32
                + ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 - '0' as i32))
                as f64;
    }
    cur = unsafe { cur.offset(2 as i32 as isize) };
    if ret == 0 && (unsafe { *cur }) as i32 == '.' as i32 {
        let mut mult: f64 = 1 as i32 as f64;
        cur = unsafe { cur.offset(1) };
        if ((unsafe { *cur }) as i32) < '0' as i32 || (unsafe { *cur }) as i32 > '9' as i32 {
            ret = 1 as i32;
        }
        while (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
            mult /= 10 as i32 as f64;
            (*(borrow_mut(&mut dt)).unwrap()).sec +=
                ((unsafe { *cur }) as i32 - '0' as i32) as f64 * mult;
            cur = unsafe { cur.offset(1) };
        }
    }
    if ret != 0 as i32 {
        return ret;
    }
    if !(((*(borrow(&dt)).unwrap()).hour() as i32 >= 0 as i32
        && (*(borrow(&dt)).unwrap()).hour() as i32 <= 23 as i32
        && ((*(borrow(&dt)).unwrap()).min() as i32 >= 0 as i32
            && (*(borrow(&dt)).unwrap()).min() as i32 <= 59 as i32)
        && ((*(borrow(&dt)).unwrap()).sec >= 0 as i32 as f64
            && (*(borrow(&dt)).unwrap()).sec < 60 as i32 as f64)
        || (*(borrow(&dt)).unwrap()).hour() as i32 == 24 as i32
            && (*(borrow(&dt)).unwrap()).min() as i32 == 0 as i32
            && (*(borrow(&dt)).unwrap()).sec == 0 as i32 as f64)
        && ((*(borrow(&dt)).unwrap()).tzo() >= -(840 as i32)
            && (*(borrow(&dt)).unwrap()).tzo() <= 840 as i32))
    {
        return 2 as i32;
    }
    *(borrow_mut(&mut str)).unwrap() = cur;
    return 0 as i32;
}
extern "C" fn _xmlSchemaParseTimeZone<'a1>(
    mut dt: *mut crate::src::xmlschemastypes::_xmlSchemaValDate,
    mut str: Option<&'a1 mut *const u8>,
) -> i32 {
    let mut cur: *const u8 = 0 as *const xmlChar;
    let mut ret: i32 = 0 as i32;
    if borrow(&str).is_none() {
        return -(1 as i32);
    }
    cur = *(borrow(&str)).unwrap();
    match (unsafe { *cur }) as i32 {
        0 => {
            (unsafe { (*dt).set_tz_flag(0 as i32 as u32) });
            (unsafe { (*dt).set_tzo(0 as i32) });
        }
        90 => {
            (unsafe { (*dt).set_tz_flag(1 as i32 as u32) });
            (unsafe { (*dt).set_tzo(0 as i32) });
            cur = unsafe { cur.offset(1) };
        }
        43 | 45 => {
            let mut isneg: i32 = 0 as i32;
            let mut tmp: i32 = 0 as i32;
            isneg = ((unsafe { *cur }) as i32 == '-' as i32) as i32;
            cur = unsafe { cur.offset(1) };
            if ((unsafe { *cur.offset(0 as i32 as isize) }) as i32) < '0' as i32
                || (unsafe { *cur.offset(0 as i32 as isize) }) as i32 > '9' as i32
                || ((unsafe { *cur.offset(1 as i32 as isize) }) as i32) < '0' as i32
                || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 > '9' as i32
            {
                ret = 1 as i32;
            } else {
                tmp = ((unsafe { *cur.offset(0 as i32 as isize) }) as i32 - '0' as i32) * 10 as i32
                    + ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 - '0' as i32);
            }
            cur = unsafe { cur.offset(2 as i32 as isize) };
            if ret != 0 as i32 {
                return ret;
            }
            if !(tmp >= 0 as i32 && tmp <= 23 as i32) {
                return 2 as i32;
            }
            if (unsafe { *cur }) as i32 != ':' as i32 {
                return 1 as i32;
            }
            cur = unsafe { cur.offset(1) };
            (unsafe { (*dt).set_tzo(tmp * 60 as i32) });
            if ((unsafe { *cur.offset(0 as i32 as isize) }) as i32) < '0' as i32
                || (unsafe { *cur.offset(0 as i32 as isize) }) as i32 > '9' as i32
                || ((unsafe { *cur.offset(1 as i32 as isize) }) as i32) < '0' as i32
                || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 > '9' as i32
            {
                ret = 1 as i32;
            } else {
                tmp = ((unsafe { *cur.offset(0 as i32 as isize) }) as i32 - '0' as i32) * 10 as i32
                    + ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 - '0' as i32);
            }
            cur = unsafe { cur.offset(2 as i32 as isize) };
            if ret != 0 as i32 {
                return ret;
            }
            if !(tmp >= 0 as i32 && tmp <= 59 as i32) {
                return 2 as i32;
            }
            (unsafe { (*dt).set_tzo((*dt).tzo() + tmp) });
            if isneg != 0 {
                (unsafe { (*dt).set_tzo(-(*dt).tzo()) });
            }
            if !((unsafe { (*dt).tzo() }) >= -(840 as i32)
                && (unsafe { (*dt).tzo() }) <= 840 as i32)
            {
                return 2 as i32;
            }
            (unsafe { (*dt).set_tz_flag(1 as i32 as u32) });
        }
        _ => return 1 as i32,
    }
    *(borrow_mut(&mut str)).unwrap() = cur;
    return 0 as i32;
}
extern "C" fn _xmlSchemaBase64Decode(ch: u8) -> i32 {
    if 'A' as i32 <= ch as i32 && ch as i32 <= 'Z' as i32 {
        return ch as i32 - 'A' as i32;
    }
    if 'a' as i32 <= ch as i32 && ch as i32 <= 'z' as i32 {
        return ch as i32 - 'a' as i32 + 26 as i32;
    }
    if '0' as i32 <= ch as i32 && ch as i32 <= '9' as i32 {
        return ch as i32 - '0' as i32 + 52 as i32;
    }
    if '+' as i32 == ch as i32 {
        return 62 as i32;
    }
    if '/' as i32 == ch as i32 {
        return 63 as i32;
    }
    if '=' as i32 == ch as i32 {
        return 64 as i32;
    }
    return -(1 as i32);
}
extern "C" fn xmlSchemaValidateDates<'a1>(
    mut type_0: u32,
    mut dateTime: *const u8,
    mut val: Option<&'a1 mut *mut crate::src::xmlschemastypes::_xmlSchemaVal>,
    mut collapse: i32,
) -> i32 {
    let mut current_block: u64;
    let mut dt: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    let mut ret: i32 = 0;
    let mut cur: *const u8 = dateTime;
    if dateTime.is_null() {
        return -(1 as i32);
    }
    if collapse != 0 {
        while (unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32
        {
            cur = unsafe { cur.offset(1) };
        }
    }
    if (unsafe { *cur }) as i32 != '-' as i32
        && ((unsafe { *cur }) as i32) < '0' as i32
        && (unsafe { *cur }) as i32 > '9' as i32
    {
        return 1 as i32;
    }
    dt = xmlSchemaNewValue(XML_SCHEMAS_UNKNOWN);
    if dt.is_null() {
        return -(1 as i32);
    }
    if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '-' as i32
        && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '-' as i32
    {
        cur = unsafe { cur.offset(2 as i32 as isize) };
        if (unsafe { *cur }) as i32 == '-' as i32 {
            if type_0 as u32 == XML_SCHEMAS_GMONTH as i32 as u32 {
                current_block = 2568818999146507592;
            } else {
                cur = unsafe { cur.offset(1) };
                ret = _xmlSchemaParseGDay(Some(unsafe { &mut (*dt).value.date }), Some(&mut cur));
                if ret != 0 as i32 {
                    current_block = 2568818999146507592;
                } else if (unsafe { *cur }) as i32 == 0 as i32
                    || (unsafe { *cur }) as i32 == 'Z' as i32
                    || (unsafe { *cur }) as i32 == '+' as i32
                    || (unsafe { *cur }) as i32 == '-' as i32
                {
                    ret =
                        _xmlSchemaParseTimeZone(unsafe { &mut (*dt).value.date }, Some(&mut cur));
                    if ret == 0 as i32 {
                        if (unsafe { *cur }) as i32 != 0 as i32 {
                            current_block = 2568818999146507592;
                        } else {
                            (unsafe { (*dt).type_0 = XML_SCHEMAS_GDAY });
                            current_block = 11781036148129668211;
                        }
                    } else {
                        current_block = 2568818999146507592;
                    }
                } else {
                    current_block = 2568818999146507592;
                }
            }
        } else {
            ret = _xmlSchemaParseGMonth(Some(unsafe { &mut (*dt).value.date }), Some(&mut cur));
            if ret != 0 as i32 {
                current_block = 2568818999146507592;
            } else {
                if (unsafe { *cur }) as i32 == '-' as i32 {
                    let mut rewnd: *const u8 = cur;
                    cur = unsafe { cur.offset(1) };
                    ret = _xmlSchemaParseGDay(
                        Some(unsafe { &mut (*dt).value.date }),
                        Some(&mut cur),
                    );
                    if ret == 0 as i32
                        && ((unsafe { *cur }) as i32 == 0 as i32
                            || (unsafe { *cur }) as i32 != ':' as i32)
                    {
                        if if (unsafe { (*dt).value.date.year }) % 4 as i32 as i64
                            == 0 as i32 as i64
                            && (unsafe { (*dt).value.date.year }) % 100 as i32 as i64
                                != 0 as i32 as i64
                            || (unsafe { (*dt).value.date.year }) % 400 as i32 as i64
                                == 0 as i32 as i64
                        {
                            ((unsafe { ((*dt).value.date).day() })
                                <= (unsafe {
                                    daysInMonthLeap
                                        [(((*dt).value.date).mon() as i32 - 1 as i32) as usize]
                                })) as i32
                        } else {
                            ((unsafe { ((*dt).value.date).day() })
                                <= (unsafe {
                                    daysInMonth
                                        [(((*dt).value.date).mon() as i32 - 1 as i32) as usize]
                                })) as i32
                        } != 0
                        {
                            if (unsafe { *cur }) as i32 == 0 as i32
                                || (unsafe { *cur }) as i32 == 'Z' as i32
                                || (unsafe { *cur }) as i32 == '+' as i32
                                || (unsafe { *cur }) as i32 == '-' as i32
                            {
                                ret = _xmlSchemaParseTimeZone(
                                    unsafe { &mut (*dt).value.date },
                                    Some(&mut cur),
                                );
                                if ret == 0 as i32 {
                                    if (unsafe { *cur }) as i32 != 0 as i32 {
                                        current_block = 2568818999146507592;
                                    } else {
                                        (unsafe { (*dt).type_0 = XML_SCHEMAS_GMONTHDAY });
                                        current_block = 11781036148129668211;
                                    }
                                } else {
                                    current_block = 2568818999146507592;
                                }
                            } else {
                                current_block = 2568818999146507592;
                            }
                        } else {
                            current_block = 15090052786889560393;
                        }
                    } else {
                        current_block = 15090052786889560393;
                    }
                    match current_block {
                        11781036148129668211 => {}
                        2568818999146507592 => {}
                        _ => {
                            cur = rewnd;
                            current_block = 18435049525520518667;
                        }
                    }
                } else {
                    current_block = 18435049525520518667;
                }
                match current_block {
                    2568818999146507592 => {}
                    11781036148129668211 => {}
                    _ => {
                        if (unsafe { *cur }) as i32 == 0 as i32
                            || (unsafe { *cur }) as i32 == 'Z' as i32
                            || (unsafe { *cur }) as i32 == '+' as i32
                            || (unsafe { *cur }) as i32 == '-' as i32
                        {
                            ret = _xmlSchemaParseTimeZone(
                                unsafe { &mut (*dt).value.date },
                                Some(&mut cur),
                            );
                            if ret == 0 as i32 {
                                if (unsafe { *cur }) as i32 != 0 as i32 {
                                    current_block = 2568818999146507592;
                                } else {
                                    (unsafe { (*dt).type_0 = XML_SCHEMAS_GMONTH });
                                    current_block = 11781036148129668211;
                                }
                            } else {
                                current_block = 2568818999146507592;
                            }
                        } else {
                            current_block = 2568818999146507592;
                        }
                    }
                }
            }
        }
    } else {
        if (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
            ret = _xmlSchemaParseTime(Some(unsafe { &mut (*dt).value.date }), Some(&mut cur));
            if ret == 0 as i32 {
                if (unsafe { *cur }) as i32 == 0 as i32
                    || (unsafe { *cur }) as i32 == 'Z' as i32
                    || (unsafe { *cur }) as i32 == '+' as i32
                    || (unsafe { *cur }) as i32 == '-' as i32
                {
                    ret =
                        _xmlSchemaParseTimeZone(unsafe { &mut (*dt).value.date }, Some(&mut cur));
                    if ret == 0 as i32 {
                        if (unsafe { *cur }) as i32 != 0 as i32 {
                            current_block = 2568818999146507592;
                        } else {
                            (unsafe { (*dt).type_0 = XML_SCHEMAS_TIME });
                            current_block = 11781036148129668211;
                        }
                    } else {
                        current_block = 17836213544692497527;
                    }
                } else {
                    current_block = 17836213544692497527;
                }
            } else {
                current_block = 17836213544692497527;
            }
        } else {
            current_block = 17836213544692497527;
        }
        match current_block {
            2568818999146507592 => {}
            11781036148129668211 => {}
            _ => {
                cur = dateTime;
                ret =
                    _xmlSchemaParseGYear(Some(unsafe { &mut (*dt).value.date }), Some(&mut cur));
                if ret != 0 as i32 {
                    current_block = 2568818999146507592;
                } else {
                    if (unsafe { *cur }) as i32 == 0 as i32
                        || (unsafe { *cur }) as i32 == 'Z' as i32
                        || (unsafe { *cur }) as i32 == '+' as i32
                        || (unsafe { *cur }) as i32 == '-' as i32
                    {
                        ret = _xmlSchemaParseTimeZone(
                            unsafe { &mut (*dt).value.date },
                            Some(&mut cur),
                        );
                        if ret == 0 as i32 {
                            if (unsafe { *cur }) as i32 != 0 as i32 {
                                current_block = 2568818999146507592;
                            } else {
                                (unsafe { (*dt).type_0 = XML_SCHEMAS_GYEAR });
                                current_block = 11781036148129668211;
                            }
                        } else {
                            current_block = 7858101417678297991;
                        }
                    } else {
                        current_block = 7858101417678297991;
                    }
                    match current_block {
                        2568818999146507592 => {}
                        11781036148129668211 => {}
                        _ => {
                            if (unsafe { *cur }) as i32 != '-' as i32 {
                                current_block = 2568818999146507592;
                            } else {
                                cur = unsafe { cur.offset(1) };
                                ret = _xmlSchemaParseGMonth(
                                    Some(unsafe { &mut (*dt).value.date }),
                                    Some(&mut cur),
                                );
                                if ret != 0 as i32 {
                                    current_block = 2568818999146507592;
                                } else {
                                    if (unsafe { *cur }) as i32 == 0 as i32
                                        || (unsafe { *cur }) as i32 == 'Z' as i32
                                        || (unsafe { *cur }) as i32 == '+' as i32
                                        || (unsafe { *cur }) as i32 == '-' as i32
                                    {
                                        ret = _xmlSchemaParseTimeZone(
                                            unsafe { &mut (*dt).value.date },
                                            Some(&mut cur),
                                        );
                                        if ret == 0 as i32 {
                                            if (unsafe { *cur }) as i32 != 0 as i32 {
                                                current_block = 2568818999146507592;
                                            } else {
                                                (unsafe { (*dt).type_0 = XML_SCHEMAS_GYEARMONTH });
                                                current_block = 11781036148129668211;
                                            }
                                        } else {
                                            current_block = 2472048668343472511;
                                        }
                                    } else {
                                        current_block = 2472048668343472511;
                                    }
                                    match current_block {
                                        2568818999146507592 => {}
                                        11781036148129668211 => {}
                                        _ => {
                                            if (unsafe { *cur }) as i32 != '-' as i32 {
                                                current_block = 2568818999146507592;
                                            } else {
                                                cur = unsafe { cur.offset(1) };
                                                ret = _xmlSchemaParseGDay(
                                                    Some(unsafe { &mut (*dt).value.date }),
                                                    Some(&mut cur),
                                                );
                                                if ret != 0 as i32
                                                    || !((unsafe { (*dt).value.date.year })
                                                        != 0 as i32 as i64
                                                        && ((unsafe { ((*dt).value.date).mon() })
                                                            as i32
                                                            >= 1 as i32
                                                            && (unsafe { ((*dt).value.date).mon() })
                                                                as i32
                                                                <= 12 as i32)
                                                        && (if (unsafe { (*dt).value.date.year })
                                                            % 4 as i32 as i64
                                                            == 0 as i32 as i64
                                                            && (unsafe { (*dt).value.date.year })
                                                                % 100 as i32 as i64
                                                                != 0 as i32 as i64
                                                            || (unsafe { (*dt).value.date.year })
                                                                % 400 as i32 as i64
                                                                == 0 as i32 as i64
                                                        {
                                                            ((unsafe { ((*dt).value.date).day() })
                                                                <= (unsafe {
                                                                    daysInMonthLeap[(((*dt)
                                                                        .value
                                                                        .date)
                                                                        .mon()
                                                                        as i32
                                                                        - 1 as i32)
                                                                        as usize]
                                                                }))
                                                                as i32
                                                        } else {
                                                            ((unsafe { ((*dt).value.date).day() })
                                                                <= (unsafe {
                                                                    daysInMonth[(((*dt).value.date)
                                                                        .mon()
                                                                        as i32
                                                                        - 1 as i32)
                                                                        as usize]
                                                                }))
                                                                as i32
                                                        }) != 0)
                                                {
                                                    current_block = 2568818999146507592;
                                                } else {
                                                    if (unsafe { *cur }) as i32 == 0 as i32
                                                        || (unsafe { *cur }) as i32 == 'Z' as i32
                                                        || (unsafe { *cur }) as i32 == '+' as i32
                                                        || (unsafe { *cur }) as i32 == '-' as i32
                                                    {
                                                        ret = _xmlSchemaParseTimeZone(
                                                            unsafe { &mut (*dt).value.date },
                                                            Some(&mut cur),
                                                        );
                                                        if ret == 0 as i32 {
                                                            if (unsafe { *cur }) as i32 != 0 as i32
                                                            {
                                                                current_block = 2568818999146507592;
                                                            } else {
                                                                (unsafe {
                                                                    (*dt).type_0 = XML_SCHEMAS_DATE
                                                                });
                                                                current_block =
                                                                    11781036148129668211;
                                                            }
                                                        } else {
                                                            current_block = 178030534879405462;
                                                        }
                                                    } else {
                                                        current_block = 178030534879405462;
                                                    }
                                                    match current_block {
                                                        11781036148129668211 => {}
                                                        2568818999146507592 => {}
                                                        _ => {
                                                            if (unsafe { *cur }) as i32
                                                                != 'T' as i32
                                                            {
                                                                current_block = 2568818999146507592;
                                                            } else {
                                                                cur = unsafe { cur.offset(1) };
                                                                ret = _xmlSchemaParseTime(
                                                                    Some(
                                                                        unsafe {
                                                                            &mut (*dt).value.date
                                                                        },
                                                                    ),
                                                                    Some(&mut cur),
                                                                );
                                                                if ret != 0 as i32 {
                                                                    current_block =
                                                                        2568818999146507592;
                                                                } else {
                                                                    ret = _xmlSchemaParseTimeZone(
                                                                        unsafe {
                                                                            &mut (*dt).value.date
                                                                        },
                                                                        Some(&mut cur),
                                                                    );
                                                                    if collapse != 0 {
                                                                        while (unsafe { *cur })
                                                                            as i32
                                                                            == 0x20 as i32
                                                                            || 0x9 as i32
                                                                                <= (unsafe { *cur })
                                                                                    as i32
                                                                                && (unsafe { *cur })
                                                                                    as i32
                                                                                    <= 0xa as i32
                                                                            || (unsafe { *cur })
                                                                                as i32
                                                                                == 0xd as i32
                                                                        {
                                                                            cur = unsafe {
                                                                                cur.offset(1)
                                                                            };
                                                                        }
                                                                    }
                                                                    if ret != 0 as i32
                                                                        || (unsafe { *cur }) as i32
                                                                            != 0 as i32
                                                                        || !((unsafe {
                                                                            (*dt).value.date.year
                                                                        }) != 0 as i32 as i64
                                                                            && ((unsafe {
                                                                                ((*dt).value.date)
                                                                                    .mon()
                                                                            })
                                                                                as i32
                                                                                >= 1 as i32
                                                                                && (unsafe {
                                                                                    ((*dt)
                                                                                        .value
                                                                                        .date)
                                                                                        .mon()
                                                                                })
                                                                                    as i32
                                                                                    <= 12 as i32)
                                                                            && (if (unsafe {
                                                                                (*dt)
                                                                                    .value
                                                                                    .date
                                                                                    .year
                                                                            }) % 4 as i32
                                                                                as i64
                                                                                == 0 as i32 as i64
                                                                                && (unsafe {
                                                                                    (*dt)
                                                                                        .value
                                                                                        .date
                                                                                        .year
                                                                                }) % 100 as i32
                                                                                    as i64
                                                                                    != 0 as i32
                                                                                        as i64
                                                                                || (unsafe {
                                                                                    (*dt)
                                                                                        .value
                                                                                        .date
                                                                                        .year
                                                                                }) % 400 as i32
                                                                                    as i64
                                                                                    == 0 as i32
                                                                                        as i64
                                                                            {
                                                                                ((unsafe {
                                                                                    ((*dt)
                                                                                        .value
                                                                                        .date)
                                                                                        .day()
                                                                                }) <= (unsafe {
                                                                                    daysInMonthLeap [(((* dt) . value . date) . mon () as i32 - 1 as i32) as usize]
                                                                                }))
                                                                                    as i32
                                                                            } else {
                                                                                ((unsafe {
                                                                                    ((*dt)
                                                                                        .value
                                                                                        .date)
                                                                                        .day()
                                                                                }) <= (unsafe {
                                                                                    daysInMonth [(((* dt) . value . date) . mon () as i32 - 1 as i32) as usize]
                                                                                }))
                                                                                    as i32
                                                                            }) != 0
                                                                            && (((unsafe {
                                                                                ((*dt).value.date)
                                                                                    .hour()
                                                                            })
                                                                                as i32
                                                                                >= 0 as i32
                                                                                && (unsafe {
                                                                                    ((*dt)
                                                                                        .value
                                                                                        .date)
                                                                                        .hour()
                                                                                })
                                                                                    as i32
                                                                                    <= 23 as i32
                                                                                && ((unsafe {
                                                                                    ((*dt)
                                                                                        .value
                                                                                        .date)
                                                                                        .min()
                                                                                })
                                                                                    as i32
                                                                                    >= 0 as i32
                                                                                    && (unsafe {
                                                                                        ((*dt)
                                                                                            .value
                                                                                            .date)
                                                                                            .min()
                                                                                    })
                                                                                        as i32
                                                                                        <= 59
                                                                                            as i32)
                                                                                && ((unsafe {
                                                                                    (*dt)
                                                                                        .value
                                                                                        .date
                                                                                        .sec
                                                                                }) >= 0 as i32
                                                                                    as f64
                                                                                    && (unsafe {
                                                                                        (*dt)
                                                                                            .value
                                                                                            .date
                                                                                            .sec
                                                                                    }) < 60
                                                                                        as i32
                                                                                        as f64)
                                                                                || (unsafe {
                                                                                    ((*dt)
                                                                                        .value
                                                                                        .date)
                                                                                        .hour()
                                                                                })
                                                                                    as i32
                                                                                    == 24 as i32
                                                                                    && (unsafe {
                                                                                        ((*dt)
                                                                                            .value
                                                                                            .date)
                                                                                            .min()
                                                                                    })
                                                                                        as i32
                                                                                        == 0 as i32
                                                                                    && (unsafe {
                                                                                        (*dt)
                                                                                            .value
                                                                                            .date
                                                                                            .sec
                                                                                    }) == 0
                                                                                        as i32
                                                                                        as f64)
                                                                                && ((unsafe {
                                                                                    ((*dt)
                                                                                        .value
                                                                                        .date)
                                                                                        .tzo()
                                                                                }) >= -(840
                                                                                    as i32)
                                                                                    && (unsafe {
                                                                                        ((*dt)
                                                                                            .value
                                                                                            .date)
                                                                                            .tzo()
                                                                                    }) <= 840
                                                                                        as i32)))
                                                                    {
                                                                        current_block =
                                                                            2568818999146507592;
                                                                    } else {
                                                                        (unsafe {
                                                                            (*dt).type_0 =
                                                                                XML_SCHEMAS_DATETIME
                                                                        });
                                                                        current_block =
                                                                            11781036148129668211;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    match current_block {
        11781036148129668211 => {
            if !(type_0 as u32 != XML_SCHEMAS_UNKNOWN as i32 as u32
                && type_0 as u32 != (unsafe { (*dt).type_0 }) as u32)
            {
                if !borrow(&val).is_none() {
                    *(borrow_mut(&mut val)).unwrap() = dt;
                } else {
                    xmlSchemaFreeValue(dt);
                }
                return 0 as i32;
            }
        }
        _ => {}
    }
    if !dt.is_null() {
        xmlSchemaFreeValue(dt);
    }
    return 1 as i32;
}
extern "C" fn xmlSchemaValidateDuration<'a1, 'a2>(
    mut _type_0: *mut crate::src::xmlschemas::_xmlSchemaType<'a1>,
    mut duration: *const u8,
    mut val: Option<&'a2 mut *mut crate::src::xmlschemastypes::_xmlSchemaVal>,
    mut collapse: i32,
) -> i32 {
    let mut current_block: u64;
    let mut cur: *const u8 = duration;
    let mut dur: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    let mut isneg: i32 = 0 as i32;
    let mut seq: u32 = 0 as i32 as u32;
    let mut days: i64 = 0;
    let mut secs: i64 = 0 as i32 as i64;
    let mut sec_frac: f64 = 0.0f64;
    if duration.is_null() {
        return -(1 as i32);
    }
    if collapse != 0 {
        while (unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32
        {
            cur = unsafe { cur.offset(1) };
        }
    }
    if (unsafe { *cur }) as i32 == '-' as i32 {
        isneg = 1 as i32;
        cur = unsafe { cur.offset(1) };
    }
    let mut fresh21 = cur;
    cur = unsafe { cur.offset(1) };
    if (unsafe { *fresh21 }) as i32 != 'P' as i32 {
        return 1 as i32;
    }
    if (unsafe { *cur }) as i32 == 0 as i32 {
        return 1 as i32;
    }
    dur = xmlSchemaNewValue(XML_SCHEMAS_DURATION);
    if dur.is_null() {
        return -(1 as i32);
    }
    's_89: loop {
        if !((unsafe { *cur }) as i32 != 0 as i32) {
            current_block = 4746626699541760585;
            break;
        }
        let mut num: i64 = 0 as i32 as i64;
        let mut has_digits: u64 = 0 as i32 as size_t;
        let mut has_frac: i32 = 0 as i32;
        let desig: [u8; 6] = [
            'Y' as i32 as xmlChar,
            'M' as i32 as xmlChar,
            'D' as i32 as xmlChar,
            'H' as i32 as xmlChar,
            'M' as i32 as xmlChar,
            'S' as i32 as xmlChar,
        ];
        if seq as u64 >= ::std::mem::size_of::<[xmlChar; 6]>() as u64 {
            current_block = 14198324742166677574;
            break;
        }
        if (unsafe { *cur }) as i32 == 'T' as i32 {
            if seq > 3 as i32 as u32 {
                current_block = 14198324742166677574;
                break;
            }
            cur = unsafe { cur.offset(1) };
            seq = 3 as i32 as u32;
        } else if seq == 3 as i32 as u32 {
            current_block = 14198324742166677574;
            break;
        }
        while (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
            let mut digit: i64 = ((unsafe { *cur }) as i32 - '0' as i32) as i64;
            if num > 9223372036854775807 as i64 / 10 as i32 as i64 {
                current_block = 14198324742166677574;
                break 's_89;
            }
            num *= 10 as i32 as i64;
            if num > 9223372036854775807 as i64 - digit {
                current_block = 14198324742166677574;
                break 's_89;
            }
            num += digit;
            has_digits = 1 as i32 as size_t;
            cur = unsafe { cur.offset(1) };
        }
        if (unsafe { *cur }) as i32 == '.' as i32 {
            let mut mult: f64 = 1.0f64;
            cur = unsafe { cur.offset(1) };
            has_frac = 1 as i32;
            while (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
                mult /= 10.0f64;
                sec_frac += ((unsafe { *cur }) as i32 - '0' as i32) as f64 * mult;
                has_digits = 1 as i32 as size_t;
                cur = unsafe { cur.offset(1) };
            }
        }
        while (unsafe { *cur }) as i32 != desig[seq as usize] as i32 {
            seq = seq.wrapping_add(1);
            if seq == 3 as i32 as u32 || seq as u64 == ::std::mem::size_of::<[xmlChar; 6]>() as u64
            {
                current_block = 14198324742166677574;
                break 's_89;
            }
        }
        cur = unsafe { cur.offset(1) };
        if has_digits == 0 || has_frac != 0 && seq != 5 as i32 as u32 {
            current_block = 14198324742166677574;
            break;
        }
        match seq {
            0 => {
                if num > 9223372036854775807 as i64 / 12 as i32 as i64 {
                    current_block = 14198324742166677574;
                    break;
                }
                (unsafe { (*dur).value.dur.mon = num * 12 as i32 as i64 });
            }
            1 => {
                if (unsafe { (*dur).value.dur.mon }) > 9223372036854775807 as i64 - num {
                    current_block = 14198324742166677574;
                    break;
                }
                (unsafe { (*dur).value.dur.mon += num });
            }
            2 => {
                (unsafe { (*dur).value.dur.day = num });
            }
            3 => {
                days = num / 24 as i32 as i64;
                if (unsafe { (*dur).value.dur.day }) > 9223372036854775807 as i64 - days {
                    current_block = 14198324742166677574;
                    break;
                }
                (unsafe { (*dur).value.dur.day += days });
                secs = num % 24 as i32 as i64 * (60 as i32 * 60 as i32) as i64;
            }
            4 => {
                days = num / (24 as i32 * 60 as i32) as i64;
                if (unsafe { (*dur).value.dur.day }) > 9223372036854775807 as i64 - days {
                    current_block = 14198324742166677574;
                    break;
                }
                (unsafe { (*dur).value.dur.day += days });
                secs += num % (24 as i32 * 60 as i32) as i64 * 60 as i32 as i64;
            }
            5 => {
                days = num / (24 as i32 * (60 as i32 * 60 as i32)) as i64;
                if (unsafe { (*dur).value.dur.day }) > 9223372036854775807 as i64 - days {
                    current_block = 14198324742166677574;
                    break;
                }
                (unsafe { (*dur).value.dur.day += days });
                secs += num % (24 as i32 * (60 as i32 * 60 as i32)) as i64;
            }
            _ => {}
        }
        seq = seq.wrapping_add(1);
    }
    match current_block {
        4746626699541760585 => {
            days = secs / (24 as i32 * (60 as i32 * 60 as i32)) as i64;
            if !((unsafe { (*dur).value.dur.day }) > 9223372036854775807 as i64 - days) {
                (unsafe { (*dur).value.dur.day += days });
                (unsafe {
                    (*dur).value.dur.sec =
                        (secs % (24 as i32 * (60 as i32 * 60 as i32)) as i64) as f64 + sec_frac
                });
                if isneg != 0 {
                    (unsafe { (*dur).value.dur.mon = -(*dur).value.dur.mon });
                    (unsafe { (*dur).value.dur.day = -(*dur).value.dur.day });
                    (unsafe { (*dur).value.dur.sec = -(*dur).value.dur.sec });
                }
                if !borrow(&val).is_none() {
                    *(borrow_mut(&mut val)).unwrap() = dur;
                } else {
                    xmlSchemaFreeValue(dur);
                }
                return 0 as i32;
            }
        }
        _ => {}
    }
    if !dur.is_null() {
        xmlSchemaFreeValue(dur);
    }
    return 1 as i32;
}
extern "C" fn xmlSchemaStrip(mut value: *const u8) -> *mut u8 {
    let mut start: *const u8 = value;
    let mut end: *const u8 = 0 as *const xmlChar;
    let mut f: *const u8 = 0 as *const xmlChar;
    if value.is_null() {
        return 0 as *mut xmlChar;
    }
    while (unsafe { *start }) as i32 != 0 as i32
        && ((unsafe { *start }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *start }) as i32 && (unsafe { *start }) as i32 <= 0xa as i32
            || (unsafe { *start }) as i32 == 0xd as i32)
    {
        start = unsafe { start.offset(1) };
    }
    end = start;
    while (unsafe { *end }) as i32 != 0 as i32 {
        end = unsafe { end.offset(1) };
    }
    f = end;
    end = unsafe { end.offset(-1) };
    while end > start
        && ((unsafe { *end }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *end }) as i32 && (unsafe { *end }) as i32 <= 0xa as i32
            || (unsafe { *end }) as i32 == 0xd as i32)
    {
        end = unsafe { end.offset(-1) };
    }
    end = unsafe { end.offset(1) };
    if start == value && f == end {
        return 0 as *mut xmlChar;
    }
    return xmlStrndup(start, (unsafe { end.offset_from(start) }) as i64 as i32);
}
#[no_mangle]
pub extern "C" fn xmlSchemaWhiteSpaceReplace(mut value: *const u8) -> *mut u8 {
    let mut cur: *const u8 = value;
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    let mut mcur: *mut u8 = 0 as *mut xmlChar;
    if value.is_null() {
        return 0 as *mut xmlChar;
    }
    while (unsafe { *cur }) as i32 != 0 as i32
        && ((unsafe { *cur }) as i32 != 0xd as i32
            && (unsafe { *cur }) as i32 != 0x9 as i32
            && (unsafe { *cur }) as i32 != 0xa as i32)
    {
        cur = unsafe { cur.offset(1) };
    }
    if (unsafe { *cur }) as i32 == 0 as i32 {
        return 0 as *mut xmlChar;
    }
    ret = xmlStrdup(value);
    mcur = unsafe { ret.offset(cur.offset_from(value) as i64 as isize) };
    loop {
        if (unsafe { *mcur }) as i32 == 0xd as i32
            || (unsafe { *mcur }) as i32 == 0x9 as i32
            || (unsafe { *mcur }) as i32 == 0xa as i32
        {
            (unsafe { *mcur = ' ' as i32 as xmlChar });
        }
        mcur = unsafe { mcur.offset(1) };
        if !((unsafe { *mcur }) as i32 != 0 as i32) {
            break;
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSchemaCollapseString(mut value: *const u8) -> *mut u8 {
    let mut start: *const u8 = value;
    let mut end: *const u8 = 0 as *const xmlChar;
    let mut f: *const u8 = 0 as *const xmlChar;
    let mut g: *mut u8 = 0 as *mut xmlChar;
    let mut col: i32 = 0 as i32;
    if value.is_null() {
        return 0 as *mut xmlChar;
    }
    while (unsafe { *start }) as i32 != 0 as i32
        && ((unsafe { *start }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *start }) as i32 && (unsafe { *start }) as i32 <= 0xa as i32
            || (unsafe { *start }) as i32 == 0xd as i32)
    {
        start = unsafe { start.offset(1) };
    }
    end = start;
    while (unsafe { *end }) as i32 != 0 as i32 {
        if (unsafe { *end }) as i32 == ' ' as i32
            && ((unsafe { *end.offset(1 as i32 as isize) }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *end.offset(1 as i32 as isize) }) as i32
                    && (unsafe { *end.offset(1 as i32 as isize) }) as i32 <= 0xa as i32
                || (unsafe { *end.offset(1 as i32 as isize) }) as i32 == 0xd as i32)
        {
            col = (unsafe { end.offset_from(start) }) as i64 as i32;
            break;
        } else if (unsafe { *end }) as i32 == 0xa as i32
            || (unsafe { *end }) as i32 == 0x9 as i32
            || (unsafe { *end }) as i32 == 0xd as i32
        {
            col = (unsafe { end.offset_from(start) }) as i64 as i32;
            break;
        } else {
            end = unsafe { end.offset(1) };
        }
    }
    if col == 0 as i32 {
        f = end;
        end = unsafe { end.offset(-1) };
        while end > start
            && ((unsafe { *end }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *end }) as i32 && (unsafe { *end }) as i32 <= 0xa as i32
                || (unsafe { *end }) as i32 == 0xd as i32)
        {
            end = unsafe { end.offset(-1) };
        }
        end = unsafe { end.offset(1) };
        if start == value && f == end {
            return 0 as *mut xmlChar;
        }
        return xmlStrndup(start, (unsafe { end.offset_from(start) }) as i64 as i32);
    }
    start = xmlStrdup(start);
    if start.is_null() {
        return 0 as *mut xmlChar;
    }
    g = (unsafe { start.offset(col as isize) }) as *mut xmlChar;
    end = g;
    while (unsafe { *end }) as i32 != 0 as i32 {
        if (unsafe { *end }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *end }) as i32 && (unsafe { *end }) as i32 <= 0xa as i32
            || (unsafe { *end }) as i32 == 0xd as i32
        {
            end = unsafe { end.offset(1) };
            while (unsafe { *end }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *end }) as i32 && (unsafe { *end }) as i32 <= 0xa as i32
                || (unsafe { *end }) as i32 == 0xd as i32
            {
                end = unsafe { end.offset(1) };
            }
            if (unsafe { *end }) as i32 != 0 as i32 {
                let mut fresh22 = g;
                g = unsafe { g.offset(1) };
                (unsafe { *fresh22 = ' ' as i32 as xmlChar });
            }
        } else {
            let mut fresh23 = end;
            end = unsafe { end.offset(1) };
            let mut fresh24 = g;
            g = unsafe { g.offset(1) };
            (unsafe { *fresh24 = *fresh23 });
        }
    }
    (unsafe { *g = 0 as i32 as xmlChar });
    return start as *mut xmlChar;
}
extern "C" fn xmlSchemaValAtomicListNode<'a1, 'a2>(
    mut type_0: *mut crate::src::xmlschemas::_xmlSchemaType<'a1>,
    mut value: *const u8,
    mut ret: Option<&'a2 mut *mut crate::src::xmlschemastypes::_xmlSchemaVal>,
    mut node: *mut crate::src::threads::_xmlNode,
) -> i32
where
    'a1: 'static,
{
    let mut val: *mut u8 = 0 as *mut xmlChar;
    let mut cur: *mut u8 = 0 as *mut xmlChar;
    let mut endval: *mut u8 = 0 as *mut xmlChar;
    let mut nb_values: i32 = 0 as i32;
    let mut tmp: i32 = 0 as i32;
    if value.is_null() {
        return -(1 as i32);
    }
    val = xmlStrdup(value);
    if val.is_null() {
        return -(1 as i32);
    }
    if !borrow(&ret).is_none() {
        *(borrow_mut(&mut ret)).unwrap() = 0 as xmlSchemaValPtr;
    }
    cur = val;
    while (unsafe { *cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
        || (unsafe { *cur }) as i32 == 0xd as i32
    {
        let mut fresh25 = cur;
        cur = unsafe { cur.offset(1) };
        (unsafe { *fresh25 = 0 as i32 as xmlChar });
    }
    while (unsafe { *cur }) as i32 != 0 as i32 {
        if (unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32
        {
            (unsafe { *cur = 0 as i32 as xmlChar });
            cur = unsafe { cur.offset(1) };
            while (unsafe { *cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
                || (unsafe { *cur }) as i32 == 0xd as i32
            {
                let mut fresh26 = cur;
                cur = unsafe { cur.offset(1) };
                (unsafe { *fresh26 = 0 as i32 as xmlChar });
            }
        } else {
            nb_values += 1;
            cur = unsafe { cur.offset(1) };
            while (unsafe { *cur }) as i32 != 0 as i32
                && !((unsafe { *cur }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *cur }) as i32
                        && (unsafe { *cur }) as i32 <= 0xa as i32
                    || (unsafe { *cur }) as i32 == 0xd as i32)
            {
                cur = unsafe { cur.offset(1) };
            }
        }
    }
    if nb_values == 0 as i32 {
        (unsafe { xmlFree.expect("non-null function pointer")(val as *mut libc::c_void) });
        return nb_values;
    }
    endval = cur;
    cur = val;
    while (unsafe { *cur }) as i32 == 0 as i32 && cur != endval {
        cur = unsafe { cur.offset(1) };
    }
    while cur != endval {
        tmp = xmlSchemaValPredefTypeNode(
            type_0,
            cur,
            Option::<&'_ mut *mut crate::src::xmlschemastypes::_xmlSchemaVal>::None,
            node,
        );
        if tmp != 0 as i32 {
            break;
        }
        while (unsafe { *cur }) as i32 != 0 as i32 {
            cur = unsafe { cur.offset(1) };
        }
        while (unsafe { *cur }) as i32 == 0 as i32 && cur != endval {
            cur = unsafe { cur.offset(1) };
        }
    }
    (unsafe { xmlFree.expect("non-null function pointer")(val as *mut libc::c_void) });
    if tmp == 0 as i32 {
        return nb_values;
    }
    return -(1 as i32);
}
extern "C" fn xmlSchemaParseUInt<'a1, 'a2, 'a3, 'a4>(
    mut str: Option<&'a1 mut *const u8>,
    mut llo: Option<&'a2 mut u64>,
    mut lmi: Option<&'a3 mut u64>,
    mut lhi: Option<&'a4 mut u64>,
) -> i32 {
    let mut lo: u64 = 0 as i32 as u64;
    let mut mi: u64 = 0 as i32 as u64;
    let mut hi: u64 = 0 as i32 as u64;
    let mut tmp: *const u8 = 0 as *const xmlChar;
    let mut cur: *const u8 = *(borrow(&str)).unwrap();
    let mut ret: i32 = 0 as i32;
    let mut i: i32 = 0 as i32;
    if !((unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32) {
        return -(2 as i32);
    }
    while (unsafe { *cur }) as i32 == '0' as i32 {
        cur = unsafe { cur.offset(1) };
    }
    tmp = cur;
    while (unsafe { *tmp }) as i32 != 0 as i32
        && (unsafe { *tmp }) as i32 >= '0' as i32
        && (unsafe { *tmp }) as i32 <= '9' as i32
    {
        i += 1;
        tmp = unsafe { tmp.offset(1) };
        ret += 1;
    }
    if i > 24 as i32 {
        *(borrow_mut(&mut str)).unwrap() = tmp;
        return -(1 as i32);
    }
    while i > 16 as i32 {
        let mut fresh27 = cur;
        cur = unsafe { cur.offset(1) };
        hi = hi
            .wrapping_mul(10 as i32 as u64)
            .wrapping_add(((unsafe { *fresh27 }) as i32 - '0' as i32) as u64);
        i -= 1;
    }
    while i > 8 as i32 {
        let mut fresh28 = cur;
        cur = unsafe { cur.offset(1) };
        mi = mi
            .wrapping_mul(10 as i32 as u64)
            .wrapping_add(((unsafe { *fresh28 }) as i32 - '0' as i32) as u64);
        i -= 1;
    }
    while i > 0 as i32 {
        let mut fresh29 = cur;
        cur = unsafe { cur.offset(1) };
        lo = lo
            .wrapping_mul(10 as i32 as u64)
            .wrapping_add(((unsafe { *fresh29 }) as i32 - '0' as i32) as u64);
        i -= 1;
    }
    *(borrow_mut(&mut str)).unwrap() = cur;
    *(borrow_mut(&mut llo)).unwrap() = lo;
    *(borrow_mut(&mut lmi)).unwrap() = mi;
    *(borrow_mut(&mut lhi)).unwrap() = hi;
    return ret;
}
extern "C" fn xmlSchemaCheckLanguageType(mut value: *const u8) -> i32 {
    let mut first: i32 = 1 as i32;
    let mut len: i32 = 0 as i32;
    let mut cur: *const u8 = value;
    if value.is_null() {
        return 0 as i32;
    }
    while (unsafe { *cur.offset(0 as i32 as isize) }) as i32 != 0 as i32 {
        if !((unsafe { *cur.offset(0 as i32 as isize) }) as i32 >= 'a' as i32
            && (unsafe { *cur.offset(0 as i32 as isize) }) as i32 <= 'z' as i32
            || (unsafe { *cur.offset(0 as i32 as isize) }) as i32 >= 'A' as i32
                && (unsafe { *cur.offset(0 as i32 as isize) }) as i32 <= 'Z' as i32
            || (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '-' as i32
            || first == 0 as i32
                && (0x30 as i32 <= (unsafe { *cur.offset(0 as i32 as isize) }) as i32
                    && (unsafe { *cur.offset(0 as i32 as isize) }) as i32 <= 0x39 as i32))
        {
            return 0 as i32;
        }
        if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '-' as i32 {
            if len < 1 as i32 || len > 8 as i32 {
                return 0 as i32;
            }
            len = 0 as i32;
            first = 0 as i32;
        } else {
            len += 1;
        }
        cur = unsafe { cur.offset(1) };
    }
    if len < 1 as i32 || len > 8 as i32 {
        return 0 as i32;
    }
    return 1 as i32;
}
extern "C" fn xmlSchemaValAtomicType<'a1, 'a2>(
    mut type_0: *mut crate::src::xmlschemas::_xmlSchemaType<'a1>,
    mut value: *const u8,
    mut val: Option<&'a2 mut *mut crate::src::xmlschemastypes::_xmlSchemaVal>,
    mut node: *mut crate::src::threads::_xmlNode,
    mut flags: i32,
    mut ws: u32,
    mut normOnTheFly: i32,
    mut applyNorm: i32,
    mut createStringValue: i32,
) -> i32
where
    'a1: 'static,
{
    let mut current_block: u64;
    let mut v: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    let mut norm: *mut u8 = 0 as *mut xmlChar;
    let mut ret: i32 = 0 as i32;
    if (unsafe { xmlSchemaTypesInitialized }) == 0 as i32 {
        xmlSchemaInitTypes();
    }
    if type_0.is_null() {
        return -(1 as i32);
    }
    if value.is_null() {
        value = b"\0" as *const u8 as *const i8 as *mut xmlChar;
    }
    if !borrow(&val).is_none() {
        *(borrow_mut(&mut val)).unwrap() = 0 as xmlSchemaValPtr;
    }
    if flags == 0 as i32 && !value.is_null() {
        if (unsafe { (*type_0).builtInType }) != XML_SCHEMAS_STRING as i32
            && (unsafe { (*type_0).builtInType }) != XML_SCHEMAS_ANYTYPE as i32
            && (unsafe { (*type_0).builtInType }) != XML_SCHEMAS_ANYSIMPLETYPE as i32
        {
            if (unsafe { (*type_0).builtInType }) == XML_SCHEMAS_NORMSTRING as i32 {
                norm = xmlSchemaWhiteSpaceReplace(value);
            } else {
                norm = xmlSchemaCollapseString(value);
            }
            if !norm.is_null() {
                value = norm;
            }
        }
    }
    match unsafe { (*type_0).builtInType } {
        0 => {
            current_block = 8144989253473847324;
        }
        45 | 46 => {
            if createStringValue != 0 && !borrow(&val).is_none() {
                v = xmlSchemaNewValue(XML_SCHEMAS_ANYSIMPLETYPE);
                if !v.is_null() {
                    let fresh30 = unsafe { &mut ((*v).value.str_0) };
                    *fresh30 = xmlStrdup(value);
                    *(borrow_mut(&mut val)).unwrap() = v;
                    current_block = 8031879791157749499;
                } else {
                    current_block = 8144989253473847324;
                }
            } else {
                current_block = 8031879791157749499;
            }
        }
        1 => {
            if normOnTheFly == 0 {
                let mut cur: *const u8 = value;
                if ws as u32 == XML_SCHEMA_WHITESPACE_REPLACE as i32 as u32 {
                    loop {
                        if !((unsafe { *cur }) as i32 != 0 as i32) {
                            current_block = 1345366029464561491;
                            break;
                        }
                        if (unsafe { *cur }) as i32 == 0xd as i32
                            || (unsafe { *cur }) as i32 == 0xa as i32
                            || (unsafe { *cur }) as i32 == 0x9 as i32
                        {
                            current_block = 16644619750446575830;
                            break;
                        }
                        cur = unsafe { cur.offset(1) };
                    }
                } else if ws as u32 == XML_SCHEMA_WHITESPACE_COLLAPSE as i32 as u32 {
                    loop {
                        if !((unsafe { *cur }) as i32 != 0 as i32) {
                            current_block = 1345366029464561491;
                            break;
                        }
                        if (unsafe { *cur }) as i32 == 0xd as i32
                            || (unsafe { *cur }) as i32 == 0xa as i32
                            || (unsafe { *cur }) as i32 == 0x9 as i32
                        {
                            current_block = 16644619750446575830;
                            break;
                        }
                        if (unsafe { *cur }) as i32 == 0x20 as i32 {
                            cur = unsafe { cur.offset(1) };
                            if (unsafe { *cur }) as i32 == 0x20 as i32 {
                                current_block = 16644619750446575830;
                                break;
                            }
                        } else {
                            cur = unsafe { cur.offset(1) };
                        }
                    }
                } else {
                    current_block = 1345366029464561491;
                }
            } else {
                current_block = 1345366029464561491;
            }
            match current_block {
                16644619750446575830 => {}
                _ => {
                    if createStringValue != 0 && !borrow(&val).is_none() {
                        if applyNorm != 0 {
                            if ws as u32 == XML_SCHEMA_WHITESPACE_COLLAPSE as i32 as u32 {
                                norm = xmlSchemaCollapseString(value);
                            } else if ws as u32 == XML_SCHEMA_WHITESPACE_REPLACE as i32 as u32 {
                                norm = xmlSchemaWhiteSpaceReplace(value);
                            }
                            if !norm.is_null() {
                                value = norm;
                            }
                        }
                        v = xmlSchemaNewValue(XML_SCHEMAS_STRING);
                        if !v.is_null() {
                            let fresh31 = unsafe { &mut ((*v).value.str_0) };
                            *fresh31 = xmlStrdup(value);
                            *(borrow_mut(&mut val)).unwrap() = v;
                            current_block = 8031879791157749499;
                        } else {
                            current_block = 8144989253473847324;
                        }
                    } else {
                        current_block = 8031879791157749499;
                    }
                }
            }
        }
        2 => {
            if normOnTheFly != 0 {
                if applyNorm != 0 {
                    if ws as u32 == XML_SCHEMA_WHITESPACE_COLLAPSE as i32 as u32 {
                        norm = xmlSchemaCollapseString(value);
                    } else {
                        norm = xmlSchemaWhiteSpaceReplace(value);
                    }
                    if !norm.is_null() {
                        value = norm;
                    }
                }
                current_block = 10435735846551762309;
            } else {
                let mut cur_0: *const u8 = value;
                loop {
                    if !((unsafe { *cur_0 }) as i32 != 0 as i32) {
                        current_block = 10435735846551762309;
                        break;
                    }
                    if (unsafe { *cur_0 }) as i32 == 0xd as i32
                        || (unsafe { *cur_0 }) as i32 == 0xa as i32
                        || (unsafe { *cur_0 }) as i32 == 0x9 as i32
                    {
                        current_block = 16644619750446575830;
                        break;
                    }
                    cur_0 = unsafe { cur_0.offset(1) };
                }
            }
            match current_block {
                16644619750446575830 => {}
                _ => {
                    if !borrow(&val).is_none() {
                        v = xmlSchemaNewValue(XML_SCHEMAS_NORMSTRING);
                        if !v.is_null() {
                            let fresh32 = unsafe { &mut ((*v).value.str_0) };
                            *fresh32 = xmlStrdup(value);
                            *(borrow_mut(&mut val)).unwrap() = v;
                            current_block = 8031879791157749499;
                        } else {
                            current_block = 8144989253473847324;
                        }
                    } else {
                        current_block = 8031879791157749499;
                    }
                }
            }
        }
        3 => {
            let mut cur_1: *const u8 = value;
            let mut len: u32 = 0;
            let mut neg: u32 = 0;
            let mut integ: u32 = 0;
            let mut hasLeadingZeroes: u32 = 0;
            let mut cval: [u8; 25] = [0; 25];
            let mut cptr: *mut u8 = cval.as_mut_ptr();
            if cur_1.is_null() || (unsafe { *cur_1 }) as i32 == 0 as i32 {
                current_block = 16644619750446575830;
            } else {
                if normOnTheFly != 0 {
                    while (unsafe { *cur_1 }) as i32 == 0x20 as i32
                        || 0x9 as i32 <= (unsafe { *cur_1 }) as i32
                            && (unsafe { *cur_1 }) as i32 <= 0xa as i32
                        || (unsafe { *cur_1 }) as i32 == 0xd as i32
                    {
                        cur_1 = unsafe { cur_1.offset(1) };
                    }
                }
                neg = 0 as i32 as u32;
                if (unsafe { *cur_1 }) as i32 == '-' as i32 {
                    neg = 1 as i32 as u32;
                    cur_1 = unsafe { cur_1.offset(1) };
                } else if (unsafe { *cur_1 }) as i32 == '+' as i32 {
                    cur_1 = unsafe { cur_1.offset(1) };
                }
                if (unsafe { *cur_1 }) as i32 == 0 as i32 {
                    current_block = 16644619750446575830;
                } else {
                    len = 0 as i32 as u32;
                    integ = !(0 as u32);
                    hasLeadingZeroes = 0 as i32 as u32;
                    while (unsafe { *cur_1 }) as i32 == '0' as i32 {
                        cur_1 = unsafe { cur_1.offset(1) };
                        hasLeadingZeroes = 1 as i32 as u32;
                    }
                    if (unsafe { *cur_1 }) as i32 != 0 as i32 {
                        loop {
                            if (unsafe { *cur_1 }) as i32 >= '0' as i32
                                && (unsafe { *cur_1 }) as i32 <= '9' as i32
                            {
                                let mut fresh33 = cur_1;
                                cur_1 = unsafe { cur_1.offset(1) };
                                let mut fresh34 = cptr;
                                cptr = unsafe { cptr.offset(1) };
                                (unsafe { *fresh34 = *fresh33 });
                                len = len.wrapping_add(1);
                                if !(len < 24 as i32 as u32) {
                                    current_block = 1069630499025798221;
                                    break;
                                }
                            } else {
                                if !((unsafe { *cur_1 }) as i32 == '.' as i32) {
                                    current_block = 1069630499025798221;
                                    break;
                                }
                                cur_1 = unsafe { cur_1.offset(1) };
                                integ = len;
                                while (unsafe { *cur_1 }) as i32 >= '0' as i32
                                    && (unsafe { *cur_1 }) as i32 <= '9' as i32
                                {
                                    let mut fresh35 = cur_1;
                                    cur_1 = unsafe { cur_1.offset(1) };
                                    let mut fresh36 = cptr;
                                    cptr = unsafe { cptr.offset(1) };
                                    (unsafe { *fresh36 = *fresh35 });
                                    len = len.wrapping_add(1);
                                    if !(len < 24 as i32 as u32) {
                                        break;
                                    }
                                }
                                if len == 0 as i32 as u32 && hasLeadingZeroes == 0 {
                                    current_block = 16644619750446575830;
                                    break;
                                } else {
                                    current_block = 1069630499025798221;
                                    break;
                                }
                            }
                        }
                    } else {
                        current_block = 1069630499025798221;
                    }
                    match current_block {
                        16644619750446575830 => {}
                        _ => {
                            if normOnTheFly != 0 {
                                while (unsafe { *cur_1 }) as i32 == 0x20 as i32
                                    || 0x9 as i32 <= (unsafe { *cur_1 }) as i32
                                        && (unsafe { *cur_1 }) as i32 <= 0xa as i32
                                    || (unsafe { *cur_1 }) as i32 == 0xd as i32
                                {
                                    cur_1 = unsafe { cur_1.offset(1) };
                                }
                            }
                            if (unsafe { *cur_1 }) as i32 != 0 as i32 {
                                current_block = 16644619750446575830;
                            } else {
                                if !borrow(&val).is_none() {
                                    v = xmlSchemaNewValue(XML_SCHEMAS_DECIMAL);
                                    if !v.is_null() {
                                        if len != 0 as i32 as u32 {
                                            if integ != !(0 as u32) {
                                                while len != integ
                                                    && (unsafe {
                                                        *cptr.offset(-(1 as i32 as isize))
                                                    })
                                                        as i32
                                                        == '0' as i32
                                                {
                                                    cptr = unsafe { cptr.offset(-1) };
                                                    len = len.wrapping_sub(1);
                                                }
                                            }
                                            if len != 0 as i32 as u32 {
                                                (unsafe { *cptr = 0 as i32 as xmlChar });
                                                cptr = cval.as_mut_ptr();
                                                xmlSchemaParseUInt(
                                                    Some(&mut (cptr as *const u8)),
                                                    Some(unsafe { &mut (*v).value.decimal.lo }),
                                                    Some(unsafe { &mut (*v).value.decimal.mi }),
                                                    Some(unsafe { &mut (*v).value.decimal.hi }),
                                                );
                                            }
                                        }
                                        let fresh37 = unsafe { &mut ((*v).value.decimal) };
                                        (*fresh37).set_sign(neg);
                                        if len == 0 as i32 as u32 {
                                            let fresh38 = unsafe { &mut ((*v).value.decimal) };
                                            (*fresh38).set_total(1 as i32 as u32);
                                        } else {
                                            let fresh39 = unsafe { &mut ((*v).value.decimal) };
                                            (*fresh39).set_total(len);
                                            if integ == !(0 as u32) {
                                                let fresh40 =
                                                    unsafe { &mut ((*v).value.decimal) };
                                                (*fresh40).set_frac(0 as i32 as u32);
                                            } else {
                                                let fresh41 =
                                                    unsafe { &mut ((*v).value.decimal) };
                                                (*fresh41).set_frac(len.wrapping_sub(integ));
                                            }
                                        }
                                        *(borrow_mut(&mut val)).unwrap() = v;
                                    }
                                }
                                current_block = 8031879791157749499;
                            }
                        }
                    }
                }
            }
        }
        4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 => {
            ret = xmlSchemaValidateDates(
                (unsafe { (*type_0).builtInType }) as xmlSchemaValType,
                value,
                borrow_mut(&mut val),
                normOnTheFly,
            );
            current_block = 3184724535425162531;
        }
        12 => {
            ret = xmlSchemaValidateDuration(type_0, value, borrow_mut(&mut val), normOnTheFly);
            current_block = 3184724535425162531;
        }
        13 | 14 => {
            let mut cur_2: *const u8 = value;
            let mut neg_0: i32 = 0 as i32;
            let mut digits_before: i32 = 0 as i32;
            let mut digits_after: i32 = 0 as i32;
            if normOnTheFly != 0 {
                while (unsafe { *cur_2 }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *cur_2 }) as i32
                        && (unsafe { *cur_2 }) as i32 <= 0xa as i32
                    || (unsafe { *cur_2 }) as i32 == 0xd as i32
                {
                    cur_2 = unsafe { cur_2.offset(1) };
                }
            }
            if (unsafe { *cur_2.offset(0 as i32 as isize) }) as i32 == 'N' as i32
                && (unsafe { *cur_2.offset(1 as i32 as isize) }) as i32 == 'a' as i32
                && (unsafe { *cur_2.offset(2 as i32 as isize) }) as i32 == 'N' as i32
            {
                cur_2 = unsafe { cur_2.offset(3 as i32 as isize) };
                if (unsafe { *cur_2 }) as i32 != 0 as i32 {
                    current_block = 16644619750446575830;
                } else if !borrow(&val).is_none() {
                    if type_0 == (unsafe { xmlSchemaTypeFloatDef }) {
                        v = xmlSchemaNewValue(XML_SCHEMAS_FLOAT);
                        if !v.is_null() {
                            (unsafe { (*v).value.f = xmlXPathNAN as f32 });
                            current_block = 3414715837273685534;
                        } else {
                            xmlSchemaFreeValue(v);
                            current_block = 8144989253473847324;
                        }
                    } else {
                        v = xmlSchemaNewValue(XML_SCHEMAS_DOUBLE);
                        if !v.is_null() {
                            (unsafe { (*v).value.d = xmlXPathNAN });
                            current_block = 3414715837273685534;
                        } else {
                            xmlSchemaFreeValue(v);
                            current_block = 8144989253473847324;
                        }
                    }
                    match current_block {
                        8144989253473847324 => {}
                        _ => {
                            *(borrow_mut(&mut val)).unwrap() = v;
                            current_block = 8031879791157749499;
                        }
                    }
                } else {
                    current_block = 8031879791157749499;
                }
            } else {
                if (unsafe { *cur_2 }) as i32 == '-' as i32 {
                    neg_0 = 1 as i32;
                    cur_2 = unsafe { cur_2.offset(1) };
                }
                if (unsafe { *cur_2.offset(0 as i32 as isize) }) as i32 == 'I' as i32
                    && (unsafe { *cur_2.offset(1 as i32 as isize) }) as i32 == 'N' as i32
                    && (unsafe { *cur_2.offset(2 as i32 as isize) }) as i32 == 'F' as i32
                {
                    cur_2 = unsafe { cur_2.offset(3 as i32 as isize) };
                    if (unsafe { *cur_2 }) as i32 != 0 as i32 {
                        current_block = 16644619750446575830;
                    } else if !borrow(&val).is_none() {
                        if type_0 == (unsafe { xmlSchemaTypeFloatDef }) {
                            v = xmlSchemaNewValue(XML_SCHEMAS_FLOAT);
                            if !v.is_null() {
                                if neg_0 != 0 {
                                    (unsafe { (*v).value.f = xmlXPathNINF as f32 });
                                } else {
                                    (unsafe { (*v).value.f = xmlXPathPINF as f32 });
                                }
                                current_block = 16718638665978159145;
                            } else {
                                xmlSchemaFreeValue(v);
                                current_block = 8144989253473847324;
                            }
                        } else {
                            v = xmlSchemaNewValue(XML_SCHEMAS_DOUBLE);
                            if !v.is_null() {
                                if neg_0 != 0 {
                                    (unsafe { (*v).value.d = xmlXPathNINF });
                                } else {
                                    (unsafe { (*v).value.d = xmlXPathPINF });
                                }
                                current_block = 16718638665978159145;
                            } else {
                                xmlSchemaFreeValue(v);
                                current_block = 8144989253473847324;
                            }
                        }
                        match current_block {
                            8144989253473847324 => {}
                            _ => {
                                *(borrow_mut(&mut val)).unwrap() = v;
                                current_block = 8031879791157749499;
                            }
                        }
                    } else {
                        current_block = 8031879791157749499;
                    }
                } else {
                    if neg_0 == 0 as i32 && (unsafe { *cur_2 }) as i32 == '+' as i32 {
                        cur_2 = unsafe { cur_2.offset(1) };
                    }
                    if (unsafe { *cur_2.offset(0 as i32 as isize) }) as i32 == 0 as i32
                        || (unsafe { *cur_2.offset(0 as i32 as isize) }) as i32 == '+' as i32
                        || (unsafe { *cur_2.offset(0 as i32 as isize) }) as i32 == '-' as i32
                    {
                        current_block = 16644619750446575830;
                    } else {
                        while (unsafe { *cur_2 }) as i32 >= '0' as i32
                            && (unsafe { *cur_2 }) as i32 <= '9' as i32
                        {
                            cur_2 = unsafe { cur_2.offset(1) };
                            digits_before += 1;
                        }
                        if (unsafe { *cur_2 }) as i32 == '.' as i32 {
                            cur_2 = unsafe { cur_2.offset(1) };
                            while (unsafe { *cur_2 }) as i32 >= '0' as i32
                                && (unsafe { *cur_2 }) as i32 <= '9' as i32
                            {
                                cur_2 = unsafe { cur_2.offset(1) };
                                digits_after += 1;
                            }
                        }
                        if digits_before == 0 as i32 && digits_after == 0 as i32 {
                            current_block = 16644619750446575830;
                        } else {
                            if (unsafe { *cur_2 }) as i32 == 'e' as i32
                                || (unsafe { *cur_2 }) as i32 == 'E' as i32
                            {
                                cur_2 = unsafe { cur_2.offset(1) };
                                if (unsafe { *cur_2 }) as i32 == '-' as i32
                                    || (unsafe { *cur_2 }) as i32 == '+' as i32
                                {
                                    cur_2 = unsafe { cur_2.offset(1) };
                                }
                                while (unsafe { *cur_2 }) as i32 >= '0' as i32
                                    && (unsafe { *cur_2 }) as i32 <= '9' as i32
                                {
                                    cur_2 = unsafe { cur_2.offset(1) };
                                }
                            }
                            if normOnTheFly != 0 {
                                while (unsafe { *cur_2 }) as i32 == 0x20 as i32
                                    || 0x9 as i32 <= (unsafe { *cur_2 }) as i32
                                        && (unsafe { *cur_2 }) as i32 <= 0xa as i32
                                    || (unsafe { *cur_2 }) as i32 == 0xd as i32
                                {
                                    cur_2 = unsafe { cur_2.offset(1) };
                                }
                            }
                            if (unsafe { *cur_2 }) as i32 != 0 as i32 {
                                current_block = 16644619750446575830;
                            } else if !borrow(&val).is_none() {
                                if type_0 == (unsafe { xmlSchemaTypeFloatDef }) {
                                    v = xmlSchemaNewValue(XML_SCHEMAS_FLOAT);
                                    if !v.is_null() {
                                        if (unsafe {
                                            sscanf(
                                                value as *const i8,
                                                b"%f\0" as *const u8 as *const i8,
                                                &mut (*v).value.f as *mut f32,
                                            )
                                        }) == 1 as i32
                                        {
                                            *(borrow_mut(&mut val)).unwrap() = v;
                                            current_block = 8031879791157749499;
                                        } else {
                                            xmlSchemaFreeValue(v);
                                            current_block = 16644619750446575830;
                                        }
                                    } else {
                                        current_block = 8144989253473847324;
                                    }
                                } else {
                                    v = xmlSchemaNewValue(XML_SCHEMAS_DOUBLE);
                                    if !v.is_null() {
                                        if (unsafe {
                                            sscanf(
                                                value as *const i8,
                                                b"%lf\0" as *const u8 as *const i8,
                                                &mut (*v).value.d as *mut f64,
                                            )
                                        }) == 1 as i32
                                        {
                                            *(borrow_mut(&mut val)).unwrap() = v;
                                            current_block = 8031879791157749499;
                                        } else {
                                            xmlSchemaFreeValue(v);
                                            current_block = 16644619750446575830;
                                        }
                                    } else {
                                        current_block = 8144989253473847324;
                                    }
                                }
                            } else {
                                current_block = 8031879791157749499;
                            }
                        }
                    }
                }
            }
        }
        15 => {
            let mut cur_3: *const u8 = value;
            if normOnTheFly != 0 {
                while (unsafe { *cur_3 }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *cur_3 }) as i32
                        && (unsafe { *cur_3 }) as i32 <= 0xa as i32
                    || (unsafe { *cur_3 }) as i32 == 0xd as i32
                {
                    cur_3 = unsafe { cur_3.offset(1) };
                }
                if (unsafe { *cur_3 }) as i32 == '0' as i32 {
                    ret = 0 as i32;
                    cur_3 = unsafe { cur_3.offset(1) };
                    current_block = 717878598772063298;
                } else if (unsafe { *cur_3 }) as i32 == '1' as i32 {
                    ret = 1 as i32;
                    cur_3 = unsafe { cur_3.offset(1) };
                    current_block = 717878598772063298;
                } else if (unsafe { *cur_3 }) as i32 == 't' as i32 {
                    cur_3 = unsafe { cur_3.offset(1) };
                    let mut fresh42 = cur_3;
                    cur_3 = unsafe { cur_3.offset(1) };
                    if (unsafe { *fresh42 }) as i32 == 'r' as i32
                        && {
                            let mut fresh43 = cur_3;
                            cur_3 = unsafe { cur_3.offset(1) };
                            (unsafe { *fresh43 }) as i32 == 'u' as i32
                        }
                        && {
                            let mut fresh44 = cur_3;
                            cur_3 = unsafe { cur_3.offset(1) };
                            (unsafe { *fresh44 }) as i32 == 'e' as i32
                        }
                    {
                        ret = 1 as i32;
                        current_block = 717878598772063298;
                    } else {
                        current_block = 16644619750446575830;
                    }
                } else if (unsafe { *cur_3 }) as i32 == 'f' as i32 {
                    cur_3 = unsafe { cur_3.offset(1) };
                    let mut fresh45 = cur_3;
                    cur_3 = unsafe { cur_3.offset(1) };
                    if (unsafe { *fresh45 }) as i32 == 'a' as i32
                        && {
                            let mut fresh46 = cur_3;
                            cur_3 = unsafe { cur_3.offset(1) };
                            (unsafe { *fresh46 }) as i32 == 'l' as i32
                        }
                        && {
                            let mut fresh47 = cur_3;
                            cur_3 = unsafe { cur_3.offset(1) };
                            (unsafe { *fresh47 }) as i32 == 's' as i32
                        }
                        && {
                            let mut fresh48 = cur_3;
                            cur_3 = unsafe { cur_3.offset(1) };
                            (unsafe { *fresh48 }) as i32 == 'e' as i32
                        }
                    {
                        ret = 0 as i32;
                        current_block = 717878598772063298;
                    } else {
                        current_block = 16644619750446575830;
                    }
                } else {
                    current_block = 16644619750446575830;
                }
                match current_block {
                    16644619750446575830 => {}
                    _ => {
                        if (unsafe { *cur_3 }) as i32 != 0 as i32 {
                            while (unsafe { *cur_3 }) as i32 == 0x20 as i32
                                || 0x9 as i32 <= (unsafe { *cur_3 }) as i32
                                    && (unsafe { *cur_3 }) as i32 <= 0xa as i32
                                || (unsafe { *cur_3 }) as i32 == 0xd as i32
                            {
                                cur_3 = unsafe { cur_3.offset(1) };
                            }
                            if (unsafe { *cur_3 }) as i32 != 0 as i32 {
                                current_block = 16644619750446575830;
                            } else {
                                current_block = 17689994068582603570;
                            }
                        } else {
                            current_block = 17689994068582603570;
                        }
                    }
                }
            } else if (unsafe { *cur_3.offset(0 as i32 as isize) }) as i32 == '0' as i32
                && (unsafe { *cur_3.offset(1 as i32 as isize) }) as i32 == 0 as i32
            {
                ret = 0 as i32;
                current_block = 17689994068582603570;
            } else if (unsafe { *cur_3.offset(0 as i32 as isize) }) as i32 == '1' as i32
                && (unsafe { *cur_3.offset(1 as i32 as isize) }) as i32 == 0 as i32
            {
                ret = 1 as i32;
                current_block = 17689994068582603570;
            } else if (unsafe { *cur_3.offset(0 as i32 as isize) }) as i32 == 't' as i32
                && (unsafe { *cur_3.offset(1 as i32 as isize) }) as i32 == 'r' as i32
                && (unsafe { *cur_3.offset(2 as i32 as isize) }) as i32 == 'u' as i32
                && (unsafe { *cur_3.offset(3 as i32 as isize) }) as i32 == 'e' as i32
                && (unsafe { *cur_3.offset(4 as i32 as isize) }) as i32 == 0 as i32
            {
                ret = 1 as i32;
                current_block = 17689994068582603570;
            } else if (unsafe { *cur_3.offset(0 as i32 as isize) }) as i32 == 'f' as i32
                && (unsafe { *cur_3.offset(1 as i32 as isize) }) as i32 == 'a' as i32
                && (unsafe { *cur_3.offset(2 as i32 as isize) }) as i32 == 'l' as i32
                && (unsafe { *cur_3.offset(3 as i32 as isize) }) as i32 == 's' as i32
                && (unsafe { *cur_3.offset(4 as i32 as isize) }) as i32 == 'e' as i32
                && (unsafe { *cur_3.offset(5 as i32 as isize) }) as i32 == 0 as i32
            {
                ret = 0 as i32;
                current_block = 17689994068582603570;
            } else {
                current_block = 16644619750446575830;
            }
            match current_block {
                16644619750446575830 => {}
                _ => {
                    if !borrow(&val).is_none() {
                        v = xmlSchemaNewValue(XML_SCHEMAS_BOOLEAN);
                        if !v.is_null() {
                            (unsafe { (*v).value.b = ret });
                            *(borrow_mut(&mut val)).unwrap() = v;
                            current_block = 8031879791157749499;
                        } else {
                            current_block = 8144989253473847324;
                        }
                    } else {
                        current_block = 8031879791157749499;
                    }
                }
            }
        }
        16 => {
            let mut cur_4: *const u8 = value;
            if normOnTheFly == 0 {
                loop {
                    if !((unsafe { *cur_4 }) as i32 != 0 as i32) {
                        current_block = 10878888195156817878;
                        break;
                    }
                    if (unsafe { *cur_4 }) as i32 == 0xd as i32
                        || (unsafe { *cur_4 }) as i32 == 0xa as i32
                        || (unsafe { *cur_4 }) as i32 == 0x9 as i32
                    {
                        current_block = 16644619750446575830;
                        break;
                    }
                    if (unsafe { *cur_4 }) as i32 == ' ' as i32 {
                        cur_4 = unsafe { cur_4.offset(1) };
                        if (unsafe { *cur_4 }) as i32 == 0 as i32 {
                            current_block = 16644619750446575830;
                            break;
                        }
                        if (unsafe { *cur_4 }) as i32 == ' ' as i32 {
                            current_block = 16644619750446575830;
                            break;
                        }
                    } else {
                        cur_4 = unsafe { cur_4.offset(1) };
                    }
                }
            } else {
                current_block = 10878888195156817878;
            }
            match current_block {
                16644619750446575830 => {}
                _ => {
                    if !borrow(&val).is_none() {
                        v = xmlSchemaNewValue(XML_SCHEMAS_TOKEN);
                        if !v.is_null() {
                            let fresh49 = unsafe { &mut ((*v).value.str_0) };
                            *fresh49 = xmlStrdup(value);
                            *(borrow_mut(&mut val)).unwrap() = v;
                            current_block = 8031879791157749499;
                        } else {
                            current_block = 8144989253473847324;
                        }
                    } else {
                        current_block = 8031879791157749499;
                    }
                }
            }
        }
        17 => {
            if norm.is_null() && normOnTheFly != 0 {
                norm = xmlSchemaCollapseString(value);
                if !norm.is_null() {
                    value = norm;
                }
            }
            if xmlSchemaCheckLanguageType(value) == 1 as i32 {
                if !borrow(&val).is_none() {
                    v = xmlSchemaNewValue(XML_SCHEMAS_LANGUAGE);
                    if !v.is_null() {
                        let fresh50 = unsafe { &mut ((*v).value.str_0) };
                        *fresh50 = xmlStrdup(value);
                        *(borrow_mut(&mut val)).unwrap() = v;
                        current_block = 8031879791157749499;
                    } else {
                        current_block = 8144989253473847324;
                    }
                } else {
                    current_block = 8031879791157749499;
                }
            } else {
                current_block = 16644619750446575830;
            }
        }
        18 => {
            if xmlValidateNMToken(value, 1 as i32) == 0 as i32 {
                if !borrow(&val).is_none() {
                    v = xmlSchemaNewValue(XML_SCHEMAS_NMTOKEN);
                    if !v.is_null() {
                        let fresh51 = unsafe { &mut ((*v).value.str_0) };
                        *fresh51 = xmlStrdup(value);
                        *(borrow_mut(&mut val)).unwrap() = v;
                        current_block = 8031879791157749499;
                    } else {
                        current_block = 8144989253473847324;
                    }
                } else {
                    current_block = 8031879791157749499;
                }
            } else {
                current_block = 16644619750446575830;
            }
        }
        19 => {
            ret = xmlSchemaValAtomicListNode(
                unsafe { xmlSchemaTypeNmtokenDef },
                value,
                borrow_mut(&mut val),
                node,
            );
            if ret > 0 as i32 {
                ret = 0 as i32;
            } else {
                ret = 1 as i32;
            }
            current_block = 3184724535425162531;
        }
        20 => {
            ret = xmlValidateName(value, 1 as i32);
            if ret == 0 as i32 && !borrow(&val).is_none() && !value.is_null() {
                v = xmlSchemaNewValue(XML_SCHEMAS_NAME);
                if !v.is_null() {
                    let mut start: *const u8 = value;
                    let mut end: *const u8 = 0 as *const xmlChar;
                    while (unsafe { *start }) as i32 == 0x20 as i32
                        || 0x9 as i32 <= (unsafe { *start }) as i32
                            && (unsafe { *start }) as i32 <= 0xa as i32
                        || (unsafe { *start }) as i32 == 0xd as i32
                    {
                        start = unsafe { start.offset(1) };
                    }
                    end = start;
                    while (unsafe { *end }) as i32 != 0 as i32
                        && !((unsafe { *end }) as i32 == 0x20 as i32
                            || 0x9 as i32 <= (unsafe { *end }) as i32
                                && (unsafe { *end }) as i32 <= 0xa as i32
                            || (unsafe { *end }) as i32 == 0xd as i32)
                    {
                        end = unsafe { end.offset(1) };
                    }
                    let fresh52 = unsafe { &mut ((*v).value.str_0) };
                    *fresh52 = xmlStrndup(start, (unsafe { end.offset_from(start) }) as i64 as i32);
                    *(borrow_mut(&mut val)).unwrap() = v;
                    current_block = 3184724535425162531;
                } else {
                    current_block = 8144989253473847324;
                }
            } else {
                current_block = 3184724535425162531;
            }
        }
        21 => {
            let mut uri: *const u8 = 0 as *const xmlChar;
            let mut local: *mut u8 = 0 as *mut xmlChar;
            ret = xmlValidateQName(value, 1 as i32);
            if ret != 0 as i32 {
                current_block = 3184724535425162531;
            } else {
                if !node.is_null() {
                    let mut prefix: *mut u8 = 0 as *mut xmlChar;
                    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
                    local = xmlSplitQName2(value, Some(&mut prefix));
                    ns = xmlSearchNs(unsafe { (*node).doc }, node, prefix);
                    if ns.is_null() && !prefix.is_null() {
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void)
                        });
                        if !local.is_null() {
                            (unsafe {
                                xmlFree.expect("non-null function pointer")(
                                    local as *mut libc::c_void,
                                )
                            });
                        }
                        current_block = 16644619750446575830;
                    } else {
                        if !ns.is_null() {
                            uri = unsafe { (*ns).href };
                        }
                        if !prefix.is_null() {
                            (unsafe {
                                xmlFree.expect("non-null function pointer")(
                                    prefix as *mut libc::c_void,
                                )
                            });
                        }
                        current_block = 9032728402242067558;
                    }
                } else {
                    current_block = 9032728402242067558;
                }
                match current_block {
                    16644619750446575830 => {}
                    _ => {
                        if !borrow(&val).is_none() {
                            v = xmlSchemaNewValue(XML_SCHEMAS_QNAME);
                            if v.is_null() {
                                if !local.is_null() {
                                    (unsafe {
                                        xmlFree.expect("non-null function pointer")(
                                            local as *mut libc::c_void,
                                        )
                                    });
                                }
                                current_block = 8144989253473847324;
                            } else {
                                if !local.is_null() {
                                    let fresh53 = unsafe { &mut ((*v).value.qname.name) };
                                    *fresh53 = local;
                                } else {
                                    let fresh54 = unsafe { &mut ((*v).value.qname.name) };
                                    *fresh54 = xmlStrdup(value);
                                }
                                if !uri.is_null() {
                                    let fresh55 = unsafe { &mut ((*v).value.qname.uri) };
                                    *fresh55 = xmlStrdup(uri);
                                }
                                *(borrow_mut(&mut val)).unwrap() = v;
                                current_block = 3184724535425162531;
                            }
                        } else {
                            if !local.is_null() {
                                (unsafe {
                                    xmlFree.expect("non-null function pointer")(
                                        local as *mut libc::c_void,
                                    )
                                });
                            }
                            current_block = 3184724535425162531;
                        }
                    }
                }
            }
        }
        22 => {
            ret = xmlValidateNCName(value, 1 as i32);
            if ret == 0 as i32 && !borrow(&val).is_none() {
                v = xmlSchemaNewValue(XML_SCHEMAS_NCNAME);
                if !v.is_null() {
                    let fresh56 = unsafe { &mut ((*v).value.str_0) };
                    *fresh56 = xmlStrdup(value);
                    *(borrow_mut(&mut val)).unwrap() = v;
                    current_block = 3184724535425162531;
                } else {
                    current_block = 8144989253473847324;
                }
            } else {
                current_block = 3184724535425162531;
            }
        }
        23 => {
            ret = xmlValidateNCName(value, 1 as i32);
            if ret == 0 as i32 && !borrow(&val).is_none() {
                v = xmlSchemaNewValue(XML_SCHEMAS_ID);
                if !v.is_null() {
                    let fresh57 = unsafe { &mut ((*v).value.str_0) };
                    *fresh57 = xmlStrdup(value);
                    *(borrow_mut(&mut val)).unwrap() = v;
                    current_block = 4076512631241092329;
                } else {
                    current_block = 8144989253473847324;
                }
            } else {
                current_block = 4076512631241092329;
            }
            match current_block {
                8144989253473847324 => {}
                _ => {
                    if ret == 0 as i32
                        && !node.is_null()
                        && (unsafe { (*node).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
                    {
                        let mut attr: *mut crate::src::threads::_xmlAttr = node as xmlAttrPtr;
                        if (unsafe { (*attr).atype }) as u32 != XML_ATTRIBUTE_ID as i32 as u32 {
                            let mut res: *mut crate::src::tree::_xmlID<'_> = 0 as *mut xmlID;
                            let mut strip: *mut u8 = 0 as *mut xmlChar;
                            strip = xmlSchemaStrip(value);
                            if !strip.is_null() {
                                res = xmlAddID(
                                    0 as xmlValidCtxtPtr,
                                    unsafe { (*node).doc },
                                    strip,
                                    attr,
                                );
                                (unsafe {
                                    xmlFree.expect("non-null function pointer")(
                                        strip as *mut libc::c_void,
                                    )
                                });
                            } else {
                                res = xmlAddID(
                                    0 as xmlValidCtxtPtr,
                                    unsafe { (*node).doc },
                                    value,
                                    attr,
                                );
                            }
                            if res.is_null() {
                                ret = 2 as i32;
                            } else {
                                (unsafe { (*attr).atype = XML_ATTRIBUTE_ID });
                            }
                        }
                    }
                    current_block = 3184724535425162531;
                }
            }
        }
        24 => {
            ret = xmlValidateNCName(value, 1 as i32);
            if ret == 0 as i32 && !borrow(&val).is_none() {
                v = xmlSchemaNewValue(XML_SCHEMAS_IDREF);
                if v.is_null() {
                    current_block = 8144989253473847324;
                } else {
                    let fresh58 = unsafe { &mut ((*v).value.str_0) };
                    *fresh58 = xmlStrdup(value);
                    *(borrow_mut(&mut val)).unwrap() = v;
                    current_block = 11900320504231061096;
                }
            } else {
                current_block = 11900320504231061096;
            }
            match current_block {
                8144989253473847324 => {}
                _ => {
                    if ret == 0 as i32
                        && !node.is_null()
                        && (unsafe { (*node).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
                    {
                        let mut attr_0: *mut crate::src::threads::_xmlAttr = node as xmlAttrPtr;
                        let mut strip_0: *mut u8 = 0 as *mut xmlChar;
                        strip_0 = xmlSchemaStrip(value);
                        if !strip_0.is_null() {
                            xmlAddRef(
                                0 as xmlValidCtxtPtr,
                                unsafe { (*node).doc },
                                strip_0,
                                attr_0,
                            );
                            (unsafe {
                                xmlFree.expect("non-null function pointer")(
                                    strip_0 as *mut libc::c_void,
                                )
                            });
                        } else {
                            xmlAddRef(
                                0 as xmlValidCtxtPtr,
                                unsafe { (*node).doc },
                                value,
                                attr_0,
                            );
                        }
                        (unsafe { (*attr_0).atype = XML_ATTRIBUTE_IDREF });
                    }
                    current_block = 3184724535425162531;
                }
            }
        }
        25 => {
            ret = xmlSchemaValAtomicListNode(
                unsafe { xmlSchemaTypeIdrefDef },
                value,
                borrow_mut(&mut val),
                node,
            );
            if ret < 0 as i32 {
                ret = 2 as i32;
            } else {
                ret = 0 as i32;
            }
            if ret == 0 as i32
                && !node.is_null()
                && (unsafe { (*node).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
            {
                let mut attr_1: *mut crate::src::threads::_xmlAttr = node as xmlAttrPtr;
                (unsafe { (*attr_1).atype = XML_ATTRIBUTE_IDREFS });
            }
            current_block = 3184724535425162531;
        }
        26 => {
            let mut strip_1: *mut u8 = 0 as *mut xmlChar;
            ret = xmlValidateNCName(value, 1 as i32);
            if node.is_null() || (unsafe { (*node).doc }).is_null() {
                ret = 3 as i32;
            }
            if ret == 0 as i32 {
                let mut ent: *mut crate::src::threads::_xmlEntity =
                    0 as *mut crate::src::threads::_xmlEntity;
                strip_1 = xmlSchemaStrip(value);
                if !strip_1.is_null() {
                    ent = unsafe { xmlGetDocEntity((*node).doc, strip_1) };
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(strip_1 as *mut libc::c_void)
                    });
                } else {
                    ent = unsafe { xmlGetDocEntity((*node).doc, value) };
                }
                if ent.is_null()
                    || (unsafe { (*ent).etype }) as u32
                        != XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as i32 as u32
                {
                    ret = 4 as i32;
                }
            }
            if ret == 0 as i32 && !borrow(&val).is_none() {
                (unsafe {
                    (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                        b"xmlschemastypes.c\0" as *const u8 as *const i8,
                        2948 as i32,
                    )
                });
            }
            if ret == 0 as i32
                && !node.is_null()
                && (unsafe { (*node).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
            {
                let mut attr_2: *mut crate::src::threads::_xmlAttr = node as xmlAttrPtr;
                (unsafe { (*attr_2).atype = XML_ATTRIBUTE_ENTITY });
            }
            current_block = 3184724535425162531;
        }
        27 => {
            if node.is_null() || (unsafe { (*node).doc }).is_null() {
                if !norm.is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(norm as *mut libc::c_void)
                    });
                }
                return 3 as i32;
            } else {
                ret = xmlSchemaValAtomicListNode(
                    unsafe { xmlSchemaTypeEntityDef },
                    value,
                    borrow_mut(&mut val),
                    node,
                );
                if ret <= 0 as i32 {
                    ret = 1 as i32;
                } else {
                    ret = 0 as i32;
                }
                if ret == 0 as i32
                    && !node.is_null()
                    && (unsafe { (*node).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
                {
                    let mut attr_3: *mut crate::src::threads::_xmlAttr = node as xmlAttrPtr;
                    (unsafe { (*attr_3).atype = XML_ATTRIBUTE_ENTITIES });
                }
            }
            current_block = 3184724535425162531;
        }
        28 => {
            let mut uri_0: *mut u8 = 0 as *mut xmlChar;
            let mut local_0: *mut u8 = 0 as *mut xmlChar;
            ret = xmlValidateQName(value, 1 as i32);
            if ret == 0 as i32 && !node.is_null() {
                let mut prefix_0: *mut u8 = 0 as *mut xmlChar;
                local_0 = xmlSplitQName2(value, Some(&mut prefix_0));
                if !prefix_0.is_null() {
                    let mut ns_0: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
                    ns_0 = xmlSearchNs(unsafe { (*node).doc }, node, prefix_0);
                    if ns_0.is_null() {
                        ret = 1 as i32;
                    } else if !borrow(&val).is_none() {
                        uri_0 = xmlStrdup(unsafe { (*ns_0).href });
                    }
                }
                if !local_0.is_null() && (borrow(&val).is_none() || ret != 0 as i32) {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(local_0 as *mut libc::c_void)
                    });
                }
                if !prefix_0.is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(prefix_0 as *mut libc::c_void)
                    });
                }
            }
            if node.is_null() || (unsafe { (*node).doc }).is_null() {
                ret = 3 as i32;
            }
            if ret == 0 as i32 {
                ret = xmlValidateNotationUse(0 as xmlValidCtxtPtr, unsafe { (*node).doc }, value);
                if ret == 1 as i32 {
                    ret = 0 as i32;
                } else {
                    ret = 1 as i32;
                }
            }
            if ret == 0 as i32 && !borrow(&val).is_none() {
                v = xmlSchemaNewValue(XML_SCHEMAS_NOTATION);
                if !v.is_null() {
                    if !local_0.is_null() {
                        let fresh59 = unsafe { &mut ((*v).value.qname.name) };
                        *fresh59 = local_0;
                    } else {
                        let fresh60 = unsafe { &mut ((*v).value.qname.name) };
                        *fresh60 = xmlStrdup(value);
                    }
                    if !uri_0.is_null() {
                        let fresh61 = unsafe { &mut ((*v).value.qname.uri) };
                        *fresh61 = uri_0;
                    }
                    *(borrow_mut(&mut val)).unwrap() = v;
                    current_block = 3184724535425162531;
                } else {
                    if !local_0.is_null() {
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(
                                local_0 as *mut libc::c_void,
                            )
                        });
                    }
                    if !uri_0.is_null() {
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(uri_0 as *mut libc::c_void)
                        });
                    }
                    current_block = 8144989253473847324;
                }
            } else {
                current_block = 3184724535425162531;
            }
        }
        29 => {
            if (unsafe { *value }) as i32 != 0 as i32 {
                let mut uri_1: *mut crate::src::uri::_xmlURI = 0 as *mut xmlURI;
                let mut tmpval: *mut u8 = 0 as *mut xmlChar;
                let mut cur_5: *mut u8 = 0 as *mut xmlChar;
                if norm.is_null() && normOnTheFly != 0 {
                    norm = xmlSchemaCollapseString(value);
                    if !norm.is_null() {
                        value = norm;
                    }
                }
                tmpval = xmlStrdup(value);
                cur_5 = tmpval;
                while (unsafe { *cur_5 }) != 0 {
                    if ((unsafe { *cur_5 }) as i32) < 32 as i32
                        || (unsafe { *cur_5 }) as i32 >= 127 as i32
                        || (unsafe { *cur_5 }) as i32 == ' ' as i32
                        || (unsafe { *cur_5 }) as i32 == '<' as i32
                        || (unsafe { *cur_5 }) as i32 == '>' as i32
                        || (unsafe { *cur_5 }) as i32 == '"' as i32
                        || (unsafe { *cur_5 }) as i32 == '{' as i32
                        || (unsafe { *cur_5 }) as i32 == '}' as i32
                        || (unsafe { *cur_5 }) as i32 == '|' as i32
                        || (unsafe { *cur_5 }) as i32 == '\\' as i32
                        || (unsafe { *cur_5 }) as i32 == '^' as i32
                        || (unsafe { *cur_5 }) as i32 == '`' as i32
                        || (unsafe { *cur_5 }) as i32 == '\'' as i32
                    {
                        (unsafe { *cur_5 = '_' as i32 as xmlChar });
                    }
                    cur_5 = unsafe { cur_5.offset(1) };
                }
                uri_1 = xmlParseURI(tmpval as *const i8);
                (unsafe {
                    xmlFree.expect("non-null function pointer")(tmpval as *mut libc::c_void)
                });
                if uri_1.is_null() {
                    current_block = 16644619750446575830;
                } else {
                    xmlFreeURI(uri_1);
                    current_block = 2980441442721982033;
                }
            } else {
                current_block = 2980441442721982033;
            }
            match current_block {
                16644619750446575830 => {}
                _ => {
                    if !borrow(&val).is_none() {
                        v = xmlSchemaNewValue(XML_SCHEMAS_ANYURI);
                        if v.is_null() {
                            current_block = 8144989253473847324;
                        } else {
                            let fresh62 = unsafe { &mut ((*v).value.str_0) };
                            *fresh62 = xmlStrdup(value);
                            *(borrow_mut(&mut val)).unwrap() = v;
                            current_block = 8031879791157749499;
                        }
                    } else {
                        current_block = 8031879791157749499;
                    }
                }
            }
        }
        43 => {
            let mut cur_6: *const u8 = value;
            let mut start_0: *const u8 = 0 as *const xmlChar;
            let mut base: *mut u8 = 0 as *mut xmlChar;
            let mut total: i32 = 0;
            let mut i: i32 = 0 as i32;
            if cur_6.is_null() {
                current_block = 16644619750446575830;
            } else {
                if normOnTheFly != 0 {
                    while (unsafe { *cur_6 }) as i32 == 0x20 as i32
                        || 0x9 as i32 <= (unsafe { *cur_6 }) as i32
                            && (unsafe { *cur_6 }) as i32 <= 0xa as i32
                        || (unsafe { *cur_6 }) as i32 == 0xd as i32
                    {
                        cur_6 = unsafe { cur_6.offset(1) };
                    }
                }
                start_0 = cur_6;
                while (unsafe { *cur_6 }) as i32 >= '0' as i32
                    && (unsafe { *cur_6 }) as i32 <= '9' as i32
                    || (unsafe { *cur_6 }) as i32 >= 'A' as i32
                        && (unsafe { *cur_6 }) as i32 <= 'F' as i32
                    || (unsafe { *cur_6 }) as i32 >= 'a' as i32
                        && (unsafe { *cur_6 }) as i32 <= 'f' as i32
                {
                    i += 1;
                    cur_6 = unsafe { cur_6.offset(1) };
                }
                if normOnTheFly != 0 {
                    while (unsafe { *cur_6 }) as i32 == 0x20 as i32
                        || 0x9 as i32 <= (unsafe { *cur_6 }) as i32
                            && (unsafe { *cur_6 }) as i32 <= 0xa as i32
                        || (unsafe { *cur_6 }) as i32 == 0xd as i32
                    {
                        cur_6 = unsafe { cur_6.offset(1) };
                    }
                }
                if (unsafe { *cur_6 }) as i32 != 0 as i32 {
                    current_block = 16644619750446575830;
                } else if i % 2 as i32 != 0 as i32 {
                    current_block = 16644619750446575830;
                } else if !borrow(&val).is_none() {
                    v = xmlSchemaNewValue(XML_SCHEMAS_HEXBINARY);
                    if v.is_null() {
                        current_block = 8144989253473847324;
                    } else {
                        cur_6 = xmlStrndup(start_0, i);
                        if cur_6.is_null() {
                            xmlSchemaTypeErrMemory(
                                node,
                                b"allocating hexbin data\0" as *const u8 as *const i8,
                            );
                            (unsafe {
                                xmlFree.expect("non-null function pointer")(v as *mut libc::c_void)
                            });
                            current_block = 16644619750446575830;
                        } else {
                            total = i / 2 as i32;
                            base = cur_6 as *mut xmlChar;
                            loop {
                                let mut fresh63 = i;
                                i = i - 1;
                                if !(fresh63 > 0 as i32) {
                                    break;
                                }
                                if (unsafe { *base }) as i32 >= 'a' as i32 {
                                    (unsafe {
                                        *base =
                                            (*base as i32 - ('a' as i32 - 'A' as i32)) as xmlChar
                                    });
                                }
                                base = unsafe { base.offset(1) };
                            }
                            let fresh64 = unsafe { &mut ((*v).value.hex.str_0) };
                            *fresh64 = cur_6 as *mut xmlChar;
                            (unsafe { (*v).value.hex.total = total as u32 });
                            *(borrow_mut(&mut val)).unwrap() = v;
                            current_block = 8031879791157749499;
                        }
                    }
                } else {
                    current_block = 8031879791157749499;
                }
            }
        }
        44 => {
            let mut cur_7: *const u8 = value;
            let mut base_0: *mut u8 = 0 as *mut xmlChar;
            let mut total_0: i32 = 0;
            let mut i_0: i32 = 0 as i32;
            let mut pad: i32 = 0 as i32;
            if cur_7.is_null() {
                current_block = 16644619750446575830;
            } else {
                while (unsafe { *cur_7 }) != 0 {
                    let mut decc: i32 = 0;
                    decc = _xmlSchemaBase64Decode(unsafe { *cur_7 });
                    if !(decc < 0 as i32) {
                        if !(decc < 64 as i32) {
                            break;
                        }
                        i_0 += 1;
                    }
                    cur_7 = unsafe { cur_7.offset(1) };
                }
                loop {
                    if !((unsafe { *cur_7 }) != 0) {
                        current_block = 14484578172259868768;
                        break;
                    }
                    let mut decc_0: i32 = 0;
                    decc_0 = _xmlSchemaBase64Decode(unsafe { *cur_7 });
                    if !(decc_0 < 0 as i32) {
                        if decc_0 < 64 as i32 {
                            current_block = 16644619750446575830;
                            break;
                        }
                    }
                    if decc_0 == 64 as i32 {
                        pad += 1;
                    }
                    cur_7 = unsafe { cur_7.offset(1) };
                }
                match current_block {
                    16644619750446575830 => {}
                    _ => {
                        total_0 = 3 as i32 * (i_0 / 4 as i32);
                        if pad == 0 as i32 {
                            if i_0 % 4 as i32 != 0 as i32 {
                                current_block = 16644619750446575830;
                            } else {
                                current_block = 5682333073795846871;
                            }
                        } else if pad == 1 as i32 {
                            let mut decc_1: i32 = 0;
                            if i_0 % 4 as i32 != 3 as i32 {
                                current_block = 16644619750446575830;
                            } else {
                                decc_1 = _xmlSchemaBase64Decode(unsafe { *cur_7 });
                                while decc_1 < 0 as i32 || decc_1 > 63 as i32 {
                                    cur_7 = unsafe { cur_7.offset(-1) };
                                    decc_1 = _xmlSchemaBase64Decode(unsafe { *cur_7 });
                                }
                                if decc_1 & !(0x3c as i32) != 0 {
                                    current_block = 16644619750446575830;
                                } else {
                                    total_0 += 2 as i32;
                                    current_block = 5682333073795846871;
                                }
                            }
                        } else if pad == 2 as i32 {
                            let mut decc_2: i32 = 0;
                            if i_0 % 4 as i32 != 2 as i32 {
                                current_block = 16644619750446575830;
                            } else {
                                decc_2 = _xmlSchemaBase64Decode(unsafe { *cur_7 });
                                while decc_2 < 0 as i32 || decc_2 > 63 as i32 {
                                    cur_7 = unsafe { cur_7.offset(-1) };
                                    decc_2 = _xmlSchemaBase64Decode(unsafe { *cur_7 });
                                }
                                if decc_2 & !(0x30 as i32) != 0 {
                                    current_block = 16644619750446575830;
                                } else {
                                    total_0 += 1 as i32;
                                    current_block = 5682333073795846871;
                                }
                            }
                        } else {
                            current_block = 16644619750446575830;
                        }
                        match current_block {
                            16644619750446575830 => {}
                            _ => {
                                if !borrow(&val).is_none() {
                                    v = xmlSchemaNewValue(XML_SCHEMAS_BASE64BINARY);
                                    if v.is_null() {
                                        current_block = 8144989253473847324;
                                    } else {
                                        base_0 = (unsafe {
                                            xmlMallocAtomic.expect("non-null function pointer")(
                                                ((i_0 + pad + 1 as i32) as u64).wrapping_mul(
                                                    ::std::mem::size_of::<xmlChar>() as u64,
                                                ),
                                            )
                                        })
                                            as *mut xmlChar;
                                        if base_0.is_null() {
                                            xmlSchemaTypeErrMemory(
                                                node,
                                                b"allocating base64 data\0" as *const u8
                                                    as *const i8,
                                            );
                                            (unsafe {
                                                xmlFree.expect("non-null function pointer")(
                                                    v as *mut libc::c_void,
                                                )
                                            });
                                            current_block = 16644619750446575830;
                                        } else {
                                            let fresh65 =
                                                unsafe { &mut ((*v).value.base64.str_0) };
                                            *fresh65 = base_0;
                                            cur_7 = value;
                                            while (unsafe { *cur_7 }) != 0 {
                                                if _xmlSchemaBase64Decode(unsafe { *cur_7 })
                                                    >= 0 as i32
                                                {
                                                    (unsafe { *base_0 = *cur_7 });
                                                    base_0 = unsafe { base_0.offset(1) };
                                                }
                                                cur_7 = unsafe { cur_7.offset(1) };
                                            }
                                            (unsafe { *base_0 = 0 as i32 as xmlChar });
                                            (unsafe { (*v).value.base64.total = total_0 as u32 });
                                            *(borrow_mut(&mut val)).unwrap() = v;
                                            current_block = 8031879791157749499;
                                        }
                                    }
                                } else {
                                    current_block = 8031879791157749499;
                                }
                            }
                        }
                    }
                }
            }
        }
        30 | 34 | 31 | 32 | 33 => {
            let mut cur_8: *const u8 = value;
            let mut lo: u64 = 0;
            let mut mi: u64 = 0;
            let mut hi: u64 = 0;
            let mut sign: i32 = 0 as i32;
            if cur_8.is_null() {
                current_block = 16644619750446575830;
            } else {
                if normOnTheFly != 0 {
                    while (unsafe { *cur_8 }) as i32 == 0x20 as i32
                        || 0x9 as i32 <= (unsafe { *cur_8 }) as i32
                            && (unsafe { *cur_8 }) as i32 <= 0xa as i32
                        || (unsafe { *cur_8 }) as i32 == 0xd as i32
                    {
                        cur_8 = unsafe { cur_8.offset(1) };
                    }
                }
                if (unsafe { *cur_8 }) as i32 == '-' as i32 {
                    sign = 1 as i32;
                    cur_8 = unsafe { cur_8.offset(1) };
                } else if (unsafe { *cur_8 }) as i32 == '+' as i32 {
                    cur_8 = unsafe { cur_8.offset(1) };
                }
                ret = xmlSchemaParseUInt(
                    Some(&mut cur_8),
                    Some(&mut lo),
                    Some(&mut mi),
                    Some(&mut hi),
                );
                if ret < 0 as i32 {
                    current_block = 16644619750446575830;
                } else {
                    if normOnTheFly != 0 {
                        while (unsafe { *cur_8 }) as i32 == 0x20 as i32
                            || 0x9 as i32 <= (unsafe { *cur_8 }) as i32
                                && (unsafe { *cur_8 }) as i32 <= 0xa as i32
                            || (unsafe { *cur_8 }) as i32 == 0xd as i32
                        {
                            cur_8 = unsafe { cur_8.offset(1) };
                        }
                    }
                    if (unsafe { *cur_8 }) as i32 != 0 as i32 {
                        current_block = 16644619750446575830;
                    } else {
                        if (unsafe { (*type_0).builtInType }) == XML_SCHEMAS_NPINTEGER as i32 {
                            if sign == 0 as i32
                                && (hi != 0 as i32 as u64
                                    || mi != 0 as i32 as u64
                                    || lo != 0 as i32 as u64)
                            {
                                current_block = 16644619750446575830;
                            } else {
                                current_block = 10529234500244145779;
                            }
                        } else if (unsafe { (*type_0).builtInType }) == XML_SCHEMAS_PINTEGER as i32
                        {
                            if sign == 1 as i32 {
                                current_block = 16644619750446575830;
                            } else if hi == 0 as i32 as u64
                                && mi == 0 as i32 as u64
                                && lo == 0 as i32 as u64
                            {
                                current_block = 16644619750446575830;
                            } else {
                                current_block = 10529234500244145779;
                            }
                        } else if (unsafe { (*type_0).builtInType }) == XML_SCHEMAS_NINTEGER as i32
                        {
                            if sign == 0 as i32 {
                                current_block = 16644619750446575830;
                            } else if hi == 0 as i32 as u64
                                && mi == 0 as i32 as u64
                                && lo == 0 as i32 as u64
                            {
                                current_block = 16644619750446575830;
                            } else {
                                current_block = 10529234500244145779;
                            }
                        } else if (unsafe { (*type_0).builtInType }) == XML_SCHEMAS_NNINTEGER as i32
                        {
                            if sign == 1 as i32
                                && (hi != 0 as i32 as u64
                                    || mi != 0 as i32 as u64
                                    || lo != 0 as i32 as u64)
                            {
                                current_block = 16644619750446575830;
                            } else {
                                current_block = 10529234500244145779;
                            }
                        } else {
                            current_block = 10529234500244145779;
                        }
                        match current_block {
                            16644619750446575830 => {}
                            _ => {
                                if !borrow(&val).is_none() {
                                    v = xmlSchemaNewValue(
                                        (unsafe { (*type_0).builtInType }) as xmlSchemaValType,
                                    );
                                    if !v.is_null() {
                                        if ret == 0 as i32 {
                                            ret += 1;
                                        }
                                        (unsafe { (*v).value.decimal.lo = lo });
                                        (unsafe { (*v).value.decimal.mi = mi });
                                        (unsafe { (*v).value.decimal.hi = hi });
                                        let fresh66 = unsafe { &mut ((*v).value.decimal) };
                                        (*fresh66).set_sign(sign as u32);
                                        let fresh67 = unsafe { &mut ((*v).value.decimal) };
                                        (*fresh67).set_frac(0 as i32 as u32);
                                        let fresh68 = unsafe { &mut ((*v).value.decimal) };
                                        (*fresh68).set_total(ret as u32);
                                        *(borrow_mut(&mut val)).unwrap() = v;
                                    }
                                }
                                current_block = 8031879791157749499;
                            }
                        }
                    }
                }
            }
        }
        37 | 41 | 39 | 35 => {
            let mut cur_9: *const u8 = value;
            let mut lo_0: u64 = 0;
            let mut mi_0: u64 = 0;
            let mut hi_0: u64 = 0;
            let mut sign_0: i32 = 0 as i32;
            if cur_9.is_null() {
                current_block = 16644619750446575830;
            } else {
                if normOnTheFly != 0 {
                    while (unsafe { *cur_9 }) as i32 == 0x20 as i32
                        || 0x9 as i32 <= (unsafe { *cur_9 }) as i32
                            && (unsafe { *cur_9 }) as i32 <= 0xa as i32
                        || (unsafe { *cur_9 }) as i32 == 0xd as i32
                    {
                        cur_9 = unsafe { cur_9.offset(1) };
                    }
                }
                if (unsafe { *cur_9 }) as i32 == '-' as i32 {
                    sign_0 = 1 as i32;
                    cur_9 = unsafe { cur_9.offset(1) };
                } else if (unsafe { *cur_9 }) as i32 == '+' as i32 {
                    cur_9 = unsafe { cur_9.offset(1) };
                }
                ret = xmlSchemaParseUInt(
                    Some(&mut cur_9),
                    Some(&mut lo_0),
                    Some(&mut mi_0),
                    Some(&mut hi_0),
                );
                if ret < 0 as i32 {
                    current_block = 16644619750446575830;
                } else {
                    if normOnTheFly != 0 {
                        while (unsafe { *cur_9 }) as i32 == 0x20 as i32
                            || 0x9 as i32 <= (unsafe { *cur_9 }) as i32
                                && (unsafe { *cur_9 }) as i32 <= 0xa as i32
                            || (unsafe { *cur_9 }) as i32 == 0xd as i32
                        {
                            cur_9 = unsafe { cur_9.offset(1) };
                        }
                    }
                    if (unsafe { *cur_9 }) as i32 != 0 as i32 {
                        current_block = 16644619750446575830;
                    } else {
                        if (unsafe { (*type_0).builtInType }) == XML_SCHEMAS_LONG as i32 {
                            if hi_0 >= 922 as i32 as u64 {
                                if hi_0 > 922 as i32 as u64 {
                                    current_block = 16644619750446575830;
                                } else if mi_0 >= 33720368 as i32 as u64 {
                                    if mi_0 > 33720368 as i32 as u64 {
                                        current_block = 16644619750446575830;
                                    } else if sign_0 == 0 as i32 && lo_0 > 54775807 as i32 as u64 {
                                        current_block = 16644619750446575830;
                                    } else if sign_0 == 1 as i32 && lo_0 > 54775808 as i32 as u64 {
                                        current_block = 16644619750446575830;
                                    } else {
                                        current_block = 7262349442925603226;
                                    }
                                } else {
                                    current_block = 7262349442925603226;
                                }
                            } else {
                                current_block = 7262349442925603226;
                            }
                        } else if (unsafe { (*type_0).builtInType }) == XML_SCHEMAS_INT as i32 {
                            if hi_0 != 0 as i32 as u64 {
                                current_block = 16644619750446575830;
                            } else if mi_0 >= 21 as i32 as u64 {
                                if mi_0 > 21 as i32 as u64 {
                                    current_block = 16644619750446575830;
                                } else if sign_0 == 0 as i32 && lo_0 > 47483647 as i32 as u64 {
                                    current_block = 16644619750446575830;
                                } else if sign_0 == 1 as i32 && lo_0 > 47483648 as i32 as u64 {
                                    current_block = 16644619750446575830;
                                } else {
                                    current_block = 7262349442925603226;
                                }
                            } else {
                                current_block = 7262349442925603226;
                            }
                        } else if (unsafe { (*type_0).builtInType }) == XML_SCHEMAS_SHORT as i32 {
                            if mi_0 != 0 as i32 as u64 || hi_0 != 0 as i32 as u64 {
                                current_block = 16644619750446575830;
                            } else if sign_0 == 1 as i32 && lo_0 > 32768 as i32 as u64 {
                                current_block = 16644619750446575830;
                            } else if sign_0 == 0 as i32 && lo_0 > 32767 as i32 as u64 {
                                current_block = 16644619750446575830;
                            } else {
                                current_block = 7262349442925603226;
                            }
                        } else if (unsafe { (*type_0).builtInType }) == XML_SCHEMAS_BYTE as i32 {
                            if mi_0 != 0 as i32 as u64 || hi_0 != 0 as i32 as u64 {
                                current_block = 16644619750446575830;
                            } else if sign_0 == 1 as i32 && lo_0 > 128 as i32 as u64 {
                                current_block = 16644619750446575830;
                            } else if sign_0 == 0 as i32 && lo_0 > 127 as i32 as u64 {
                                current_block = 16644619750446575830;
                            } else {
                                current_block = 7262349442925603226;
                            }
                        } else {
                            current_block = 7262349442925603226;
                        }
                        match current_block {
                            16644619750446575830 => {}
                            _ => {
                                if !borrow(&val).is_none() {
                                    v = xmlSchemaNewValue(
                                        (unsafe { (*type_0).builtInType }) as xmlSchemaValType,
                                    );
                                    if !v.is_null() {
                                        (unsafe { (*v).value.decimal.lo = lo_0 });
                                        (unsafe { (*v).value.decimal.mi = mi_0 });
                                        (unsafe { (*v).value.decimal.hi = hi_0 });
                                        let fresh69 = unsafe { &mut ((*v).value.decimal) };
                                        (*fresh69).set_sign(sign_0 as u32);
                                        let fresh70 = unsafe { &mut ((*v).value.decimal) };
                                        (*fresh70).set_frac(0 as i32 as u32);
                                        let fresh71 = unsafe { &mut ((*v).value.decimal) };
                                        (*fresh71).set_total(ret as u32);
                                        *(borrow_mut(&mut val)).unwrap() = v;
                                    }
                                }
                                current_block = 8031879791157749499;
                            }
                        }
                    }
                }
            }
        }
        36 | 38 | 40 | 42 => {
            let mut cur_10: *const u8 = value;
            let mut lo_1: u64 = 0;
            let mut mi_1: u64 = 0;
            let mut hi_1: u64 = 0;
            if cur_10.is_null() {
                current_block = 16644619750446575830;
            } else {
                if normOnTheFly != 0 {
                    while (unsafe { *cur_10 }) as i32 == 0x20 as i32
                        || 0x9 as i32 <= (unsafe { *cur_10 }) as i32
                            && (unsafe { *cur_10 }) as i32 <= 0xa as i32
                        || (unsafe { *cur_10 }) as i32 == 0xd as i32
                    {
                        cur_10 = unsafe { cur_10.offset(1) };
                    }
                }
                ret = xmlSchemaParseUInt(
                    Some(&mut cur_10),
                    Some(&mut lo_1),
                    Some(&mut mi_1),
                    Some(&mut hi_1),
                );
                if ret < 0 as i32 {
                    current_block = 16644619750446575830;
                } else {
                    if normOnTheFly != 0 {
                        while (unsafe { *cur_10 }) as i32 == 0x20 as i32
                            || 0x9 as i32 <= (unsafe { *cur_10 }) as i32
                                && (unsafe { *cur_10 }) as i32 <= 0xa as i32
                            || (unsafe { *cur_10 }) as i32 == 0xd as i32
                        {
                            cur_10 = unsafe { cur_10.offset(1) };
                        }
                    }
                    if (unsafe { *cur_10 }) as i32 != 0 as i32 {
                        current_block = 16644619750446575830;
                    } else {
                        if (unsafe { (*type_0).builtInType }) == XML_SCHEMAS_ULONG as i32 {
                            if hi_1 >= 1844 as i32 as u64 {
                                if hi_1 > 1844 as i32 as u64 {
                                    current_block = 16644619750446575830;
                                } else if mi_1 >= 67440737 as i32 as u64 {
                                    if mi_1 > 67440737 as i32 as u64 {
                                        current_block = 16644619750446575830;
                                    } else if lo_1 > 9551615 as i32 as u64 {
                                        current_block = 16644619750446575830;
                                    } else {
                                        current_block = 12374693259337570491;
                                    }
                                } else {
                                    current_block = 12374693259337570491;
                                }
                            } else {
                                current_block = 12374693259337570491;
                            }
                        } else if (unsafe { (*type_0).builtInType }) == XML_SCHEMAS_UINT as i32 {
                            if hi_1 != 0 as i32 as u64 {
                                current_block = 16644619750446575830;
                            } else if mi_1 >= 42 as i32 as u64 {
                                if mi_1 > 42 as i32 as u64 {
                                    current_block = 16644619750446575830;
                                } else if lo_1 > 94967295 as i32 as u64 {
                                    current_block = 16644619750446575830;
                                } else {
                                    current_block = 12374693259337570491;
                                }
                            } else {
                                current_block = 12374693259337570491;
                            }
                        } else if (unsafe { (*type_0).builtInType }) == XML_SCHEMAS_USHORT as i32 {
                            if mi_1 != 0 as i32 as u64 || hi_1 != 0 as i32 as u64 {
                                current_block = 16644619750446575830;
                            } else if lo_1 > 65535 as i32 as u64 {
                                current_block = 16644619750446575830;
                            } else {
                                current_block = 12374693259337570491;
                            }
                        } else if (unsafe { (*type_0).builtInType }) == XML_SCHEMAS_UBYTE as i32 {
                            if mi_1 != 0 as i32 as u64 || hi_1 != 0 as i32 as u64 {
                                current_block = 16644619750446575830;
                            } else if lo_1 > 255 as i32 as u64 {
                                current_block = 16644619750446575830;
                            } else {
                                current_block = 12374693259337570491;
                            }
                        } else {
                            current_block = 12374693259337570491;
                        }
                        match current_block {
                            16644619750446575830 => {}
                            _ => {
                                if !borrow(&val).is_none() {
                                    v = xmlSchemaNewValue(
                                        (unsafe { (*type_0).builtInType }) as xmlSchemaValType,
                                    );
                                    if !v.is_null() {
                                        (unsafe { (*v).value.decimal.lo = lo_1 });
                                        (unsafe { (*v).value.decimal.mi = mi_1 });
                                        (unsafe { (*v).value.decimal.hi = hi_1 });
                                        let fresh72 = unsafe { &mut ((*v).value.decimal) };
                                        (*fresh72).set_sign(0 as i32 as u32);
                                        let fresh73 = unsafe { &mut ((*v).value.decimal) };
                                        (*fresh73).set_frac(0 as i32 as u32);
                                        let fresh74 = unsafe { &mut ((*v).value.decimal) };
                                        (*fresh74).set_total(ret as u32);
                                        *(borrow_mut(&mut val)).unwrap() = v;
                                    }
                                }
                                current_block = 8031879791157749499;
                            }
                        }
                    }
                }
            }
        }
        _ => {
            current_block = 3184724535425162531;
        }
    }
    match current_block {
        8144989253473847324 => {
            if !norm.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(norm as *mut libc::c_void) });
            }
            return -(1 as i32);
        }
        16644619750446575830 => {
            if !norm.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(norm as *mut libc::c_void) });
            }
            return 1 as i32;
        }
        8031879791157749499 => {
            if !norm.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(norm as *mut libc::c_void) });
            }
            return 0 as i32;
        }
        _ => {
            if !norm.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(norm as *mut libc::c_void) });
            }
            return ret;
        }
    };
}
#[no_mangle]
pub extern "C" fn xmlSchemaValPredefTypeNode<'a1, 'a2>(
    mut type_0: *mut crate::src::xmlschemas::_xmlSchemaType<'a1>,
    mut value: *const u8,
    mut val: Option<&'a2 mut *mut crate::src::xmlschemastypes::_xmlSchemaVal>,
    mut node: *mut crate::src::threads::_xmlNode,
) -> i32
where
    'a1: 'static,
{
    return xmlSchemaValAtomicType(
        type_0,
        value,
        borrow_mut(&mut val),
        node,
        0 as i32,
        XML_SCHEMA_WHITESPACE_UNKNOWN,
        1 as i32,
        1 as i32,
        0 as i32,
    );
}
#[no_mangle]
pub extern "C" fn xmlSchemaValPredefTypeNodeNoNorm<'a1, 'a2>(
    mut type_0: *mut crate::src::xmlschemas::_xmlSchemaType<'a1>,
    mut value: *const u8,
    mut val: Option<&'a2 mut *mut crate::src::xmlschemastypes::_xmlSchemaVal>,
    mut node: *mut crate::src::threads::_xmlNode,
) -> i32
where
    'a1: 'static,
{
    return xmlSchemaValAtomicType(
        type_0,
        value,
        borrow_mut(&mut val),
        node,
        1 as i32,
        XML_SCHEMA_WHITESPACE_UNKNOWN,
        1 as i32,
        0 as i32,
        1 as i32,
    );
}
#[no_mangle]
pub extern "C" fn xmlSchemaValidatePredefinedType<'a1, 'a2>(
    mut type_0: *mut crate::src::xmlschemas::_xmlSchemaType<'a1>,
    mut value: *const u8,
    mut val: Option<&'a2 mut *mut crate::src::xmlschemastypes::_xmlSchemaVal>,
) -> i32
where
    'a1: 'static,
{
    return xmlSchemaValPredefTypeNode(type_0, value, borrow_mut(&mut val), 0 as xmlNodePtr);
}
extern "C" fn xmlSchemaCompareDecimals(
    mut x: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut y: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> i32 {
    let mut swp: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    let mut order: i32 = 1 as i32;
    let mut integx: i32 = 0;
    let mut integy: i32 = 0;
    let mut dlen: i32 = 0;
    let mut hi: u64 = 0;
    let mut mi: u64 = 0;
    let mut lo: u64 = 0;
    if (unsafe { ((*x).value.decimal).sign() }) as i32 != 0
        && ((unsafe { (*x).value.decimal.lo }) != 0 as i32 as u64
            || (unsafe { (*x).value.decimal.mi }) != 0 as i32 as u64
            || (unsafe { (*x).value.decimal.hi }) != 0 as i32 as u64)
    {
        if (unsafe { ((*y).value.decimal).sign() }) as i32 != 0
            && ((unsafe { (*y).value.decimal.lo }) != 0 as i32 as u64
                || (unsafe { (*y).value.decimal.mi }) != 0 as i32 as u64
                || (unsafe { (*y).value.decimal.hi }) != 0 as i32 as u64)
        {
            order = -(1 as i32);
        } else {
            return -(1 as i32);
        }
    } else if (unsafe { ((*y).value.decimal).sign() }) as i32 != 0
        && ((unsafe { (*y).value.decimal.lo }) != 0 as i32 as u64
            || (unsafe { (*y).value.decimal.mi }) != 0 as i32 as u64
            || (unsafe { (*y).value.decimal.hi }) != 0 as i32 as u64)
    {
        return 1 as i32;
    }
    integx = (unsafe { ((*x).value.decimal).total() }) as i32
        - (unsafe { ((*x).value.decimal).frac() }) as i32;
    integy = (unsafe { ((*y).value.decimal).total() }) as i32
        - (unsafe { ((*y).value.decimal).frac() }) as i32;
    if integx == 1 as i32 {
        if (unsafe { (*x).value.decimal.lo }) == 0 as i32 as u64 {
            if integy != 1 as i32 {
                return -order;
            } else if (unsafe { (*y).value.decimal.lo }) != 0 as i32 as u64 {
                return -order;
            } else {
                return 0 as i32;
            }
        }
    }
    if integy == 1 as i32 {
        if (unsafe { (*y).value.decimal.lo }) == 0 as i32 as u64 {
            if integx != 1 as i32 {
                return order;
            } else if (unsafe { (*x).value.decimal.lo }) != 0 as i32 as u64 {
                return order;
            } else {
                return 0 as i32;
            }
        }
    }
    if integx > integy {
        return order;
    } else {
        if integy > integx {
            return -order;
        }
    }
    dlen = (unsafe { ((*x).value.decimal).total() }) as i32
        - (unsafe { ((*y).value.decimal).total() }) as i32;
    if dlen < 0 as i32 {
        swp = x;
        hi = unsafe { (*y).value.decimal.hi };
        mi = unsafe { (*y).value.decimal.mi };
        lo = unsafe { (*y).value.decimal.lo };
        dlen = -dlen;
        order = -order;
    } else {
        swp = y;
        hi = unsafe { (*x).value.decimal.hi };
        mi = unsafe { (*x).value.decimal.mi };
        lo = unsafe { (*x).value.decimal.lo };
    }
    while dlen > 8 as i32 {
        lo = mi;
        mi = hi;
        hi = 0 as i32 as u64;
        dlen -= 8 as i32;
    }
    while dlen > 0 as i32 {
        let mut rem1: u64 = 0;
        let mut rem2: u64 = 0;
        rem1 = hi
            .wrapping_rem(10 as i32 as u64)
            .wrapping_mul(100000000 as i64 as u64);
        hi = hi.wrapping_div(10 as i32 as u64);
        rem2 = mi
            .wrapping_rem(10 as i32 as u64)
            .wrapping_mul(100000000 as i64 as u64);
        mi = mi.wrapping_add(rem1).wrapping_div(10 as i32 as u64);
        lo = lo.wrapping_add(rem2).wrapping_div(10 as i32 as u64);
        dlen -= 1;
    }
    if hi > (unsafe { (*swp).value.decimal.hi }) {
        return order;
    } else {
        if hi == (unsafe { (*swp).value.decimal.hi }) {
            if mi > (unsafe { (*swp).value.decimal.mi }) {
                return order;
            } else {
                if mi == (unsafe { (*swp).value.decimal.mi }) {
                    if lo > (unsafe { (*swp).value.decimal.lo }) {
                        return order;
                    } else {
                        if lo == (unsafe { (*swp).value.decimal.lo }) {
                            if (unsafe { ((*x).value.decimal).total() }) as i32
                                == (unsafe { ((*y).value.decimal).total() }) as i32
                            {
                                return 0 as i32;
                            } else {
                                return order;
                            }
                        }
                    }
                }
            }
        }
    }
    return -order;
}
extern "C" fn xmlSchemaCompareDurations(
    mut x: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut y: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> i32 {
    let mut carry: i64 = 0;
    let mut mon: i64 = 0;
    let mut day: i64 = 0;
    let mut sec: f64 = 0.;
    let mut invert: i32 = 1 as i32;
    let mut xmon: i64 = 0;
    let mut xday: i64 = 0;
    let mut myear: i64 = 0;
    let mut minday: i64 = 0;
    let mut maxday: i64 = 0;
    static mut dayRange: [[i64; 12]; 2] = [
        [
            0 as i32 as i64,
            28 as i32 as i64,
            59 as i32 as i64,
            89 as i32 as i64,
            120 as i32 as i64,
            150 as i32 as i64,
            181 as i32 as i64,
            212 as i32 as i64,
            242 as i32 as i64,
            273 as i32 as i64,
            303 as i32 as i64,
            334 as i32 as i64,
        ],
        [
            0 as i32 as i64,
            31 as i32 as i64,
            62 as i32 as i64,
            92 as i32 as i64,
            123 as i32 as i64,
            153 as i32 as i64,
            184 as i32 as i64,
            215 as i32 as i64,
            245 as i32 as i64,
            276 as i32 as i64,
            306 as i32 as i64,
            337 as i32 as i64,
        ],
    ];
    if x.is_null() || y.is_null() {
        return -(2 as i32);
    }
    mon = (unsafe { (*x).value.dur.mon }) - (unsafe { (*y).value.dur.mon });
    sec = (unsafe { (*x).value.dur.sec }) - (unsafe { (*y).value.dur.sec });
    carry = (sec / (24 as i32 * (60 as i32 * 60 as i32)) as f64) as i64;
    sec -= carry as f64 * (24 as i32 * (60 as i32 * 60 as i32)) as f64;
    day = (unsafe { (*x).value.dur.day }) - (unsafe { (*y).value.dur.day }) + carry;
    if mon == 0 as i32 as i64 {
        if day == 0 as i32 as i64 {
            if sec == 0.0f64 {
                return 0 as i32;
            } else if sec < 0.0f64 {
                return -(1 as i32);
            } else {
                return 1 as i32;
            }
        } else if day < 0 as i32 as i64 {
            return -(1 as i32);
        } else {
            return 1 as i32;
        }
    }
    if mon > 0 as i32 as i64 {
        if day >= 0 as i32 as i64 && sec >= 0.0f64 {
            return 1 as i32;
        } else {
            xmon = mon;
            xday = -day;
        }
    } else if day <= 0 as i32 as i64 && sec <= 0.0f64 {
        return -(1 as i32);
    } else {
        invert = -(1 as i32);
        xmon = -mon;
        xday = day;
    }
    myear = xmon / 12 as i32 as i64;
    if myear == 0 as i32 as i64 {
        minday = 0 as i32 as i64;
        maxday = 0 as i32 as i64;
    } else {
        if myear > 9223372036854775807 as i64 / 366 as i32 as i64 {
            return -(2 as i32);
        }
        maxday = 365 as i32 as i64 * myear + (myear + 3 as i32 as i64) / 4 as i32 as i64;
        minday = maxday - 1 as i32 as i64;
    }
    xmon = xmon % 12 as i32 as i64;
    minday += unsafe { dayRange[0 as i32 as usize][xmon as usize] };
    maxday += unsafe { dayRange[1 as i32 as usize][xmon as usize] };
    if maxday == minday && maxday == xday {
        return 0 as i32;
    }
    if maxday < xday {
        return -invert;
    }
    if minday > xday {
        return invert;
    }
    return 2 as i32;
}
extern "C" fn xmlSchemaDupVal(
    mut v: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> *mut crate::src::xmlschemastypes::_xmlSchemaVal {
    let mut ret: *mut crate::src::xmlschemastypes::_xmlSchemaVal =
        xmlSchemaNewValue(unsafe { (*v).type_0 });
    if ret.is_null() {
        return 0 as xmlSchemaValPtr;
    }
    (unsafe {
        memcpy(
            ret as *mut libc::c_void,
            v as *const libc::c_void,
            ::std::mem::size_of::<xmlSchemaVal>() as u64,
        )
    });
    let fresh75 = unsafe { &mut ((*ret).next) };
    *fresh75 = 0 as *mut _xmlSchemaVal;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSchemaCopyValue(
    mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> *mut crate::src::xmlschemastypes::_xmlSchemaVal {
    let mut ret: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as xmlSchemaValPtr;
    let mut prev: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as xmlSchemaValPtr;
    let mut cur: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    while !val.is_null() {
        match (unsafe { (*val).type_0 }) as u32 {
            45 | 25 | 27 | 19 => {
                xmlSchemaFreeValue(ret);
                return 0 as xmlSchemaValPtr;
            }
            46 | 1 | 2 | 16 | 17 | 20 | 22 | 23 | 24 | 26 | 18 | 29 => {
                cur = xmlSchemaDupVal(val);
                if !(unsafe { (*val).value.str_0 }).is_null() {
                    let fresh76 = unsafe { &mut ((*cur).value.str_0) };
                    *fresh76 = xmlStrdup(unsafe { (*val).value.str_0 });
                }
            }
            21 | 28 => {
                cur = xmlSchemaDupVal(val);
                if !(unsafe { (*val).value.qname.name }).is_null() {
                    let fresh77 = unsafe { &mut ((*cur).value.qname.name) };
                    *fresh77 = xmlStrdup(unsafe { (*val).value.qname.name });
                }
                if !(unsafe { (*val).value.qname.uri }).is_null() {
                    let fresh78 = unsafe { &mut ((*cur).value.qname.uri) };
                    *fresh78 = xmlStrdup(unsafe { (*val).value.qname.uri });
                }
            }
            43 => {
                cur = xmlSchemaDupVal(val);
                if !(unsafe { (*val).value.hex.str_0 }).is_null() {
                    let fresh79 = unsafe { &mut ((*cur).value.hex.str_0) };
                    *fresh79 = xmlStrdup(unsafe { (*val).value.hex.str_0 });
                }
            }
            44 => {
                cur = xmlSchemaDupVal(val);
                if !(unsafe { (*val).value.base64.str_0 }).is_null() {
                    let fresh80 = unsafe { &mut ((*cur).value.base64.str_0) };
                    *fresh80 = xmlStrdup(unsafe { (*val).value.base64.str_0 });
                }
            }
            _ => {
                cur = xmlSchemaDupVal(val);
            }
        }
        if ret.is_null() {
            ret = cur;
        } else {
            let fresh81 = unsafe { &mut ((*prev).next) };
            *fresh81 = cur;
        }
        prev = cur;
        val = unsafe { (*val).next };
    }
    return ret;
}
extern "C" fn _xmlSchemaDateAdd(
    mut dt: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut dur: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> *mut crate::src::xmlschemastypes::_xmlSchemaVal {
    let mut ret: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    let mut tmp: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    let mut carry: i64 = 0;
    let mut tempdays: i64 = 0;
    let mut temp: i64 = 0;
    let mut r: Option<&'_ mut crate::src::xmlschemastypes::_xmlSchemaValDate> =
        Option::<&'_ mut crate::src::xmlschemastypes::_xmlSchemaValDate>::None;
    let mut d: Option<&'_ mut crate::src::xmlschemastypes::_xmlSchemaValDate> =
        Option::<&'_ mut crate::src::xmlschemastypes::_xmlSchemaValDate>::None;
    let mut u: Option<&'_ mut crate::src::xmlschemastypes::_xmlSchemaValDuration> =
        Option::<&'_ mut crate::src::xmlschemastypes::_xmlSchemaValDuration>::None;
    if dt.is_null() || dur.is_null() {
        return 0 as xmlSchemaValPtr;
    }
    ret = xmlSchemaNewValue(unsafe { (*dt).type_0 });
    if ret.is_null() {
        return 0 as xmlSchemaValPtr;
    }
    tmp = xmlSchemaDupVal(dt);
    if tmp.is_null() {
        xmlSchemaFreeValue(ret);
        return 0 as xmlSchemaValPtr;
    }
    r = Some(unsafe { &mut (*ret).value.date });
    d = Some(unsafe { &mut (*tmp).value.date });
    u = Some(unsafe { &mut (*dur).value.dur });
    if (*(borrow(&d)).unwrap()).mon() as i32 == 0 as i32 {
        (*(borrow_mut(&mut d)).unwrap()).set_mon(1 as i32 as u32);
    }
    (*(borrow_mut(&mut u)).unwrap()).sec -= ((*(borrow(&d)).unwrap()).tzo() * 60 as i32) as f64;
    (*(borrow_mut(&mut d)).unwrap()).set_tzo(0 as i32);
    if (*(borrow(&d)).unwrap()).day() as i32 == 0 as i32 {
        (*(borrow_mut(&mut d)).unwrap()).set_day(1 as i32 as u32);
    }
    carry = (*(borrow(&d)).unwrap()).mon() as i64 + (*(borrow(&u)).unwrap()).mon;
    (*(borrow_mut(&mut r)).unwrap()).set_mon(
        ((carry - 1 as i32 as i64) as f64
            - (unsafe { floor((carry - 1 as i32 as i64) as f64 / (13 as i32 - 1 as i32) as f64) })
                * (13 as i32 - 1 as i32) as f64
            + 1 as i32 as f64) as u32,
    );
    carry =
        (unsafe { floor((carry - 1 as i32 as i64) as f64 / (13 as i32 - 1 as i32) as f64) }) as i64;
    (*(borrow_mut(&mut r)).unwrap()).year = (*(borrow(&d)).unwrap()).year + carry;
    if (*(borrow(&r)).unwrap()).year == 0 as i32 as i64 {
        if (*(borrow(&d)).unwrap()).year > 0 as i32 as i64 {
            let fresh82 = &mut ((*(borrow_mut(&mut r)).unwrap()).year);
            *fresh82 -= 1;
        } else {
            let fresh83 = &mut ((*(borrow_mut(&mut r)).unwrap()).year);
            *fresh83 += 1;
        }
    }
    (*(borrow_mut(&mut r)).unwrap()).set_tzo((*(borrow(&d)).unwrap()).tzo());
    (*(borrow_mut(&mut r)).unwrap()).set_tz_flag((*(borrow(&d)).unwrap()).tz_flag());
    (*(borrow_mut(&mut r)).unwrap()).sec =
        (*(borrow(&d)).unwrap()).sec + (*(borrow(&u)).unwrap()).sec;
    carry =
        (unsafe { floor((*(borrow(&r)).unwrap()).sec as i64 as f64 / 60 as i32 as f64) }) as i64;
    if (*(borrow(&r)).unwrap()).sec != 0.0f64 {
        (*(borrow_mut(&mut r)).unwrap()).sec = (*(borrow(&r)).unwrap()).sec
            - (unsafe { floor((*(borrow(&r)).unwrap()).sec / 60.0f64) }) * 60.0f64;
    }
    carry += (*(borrow(&d)).unwrap()).min() as i64;
    (*(borrow_mut(&mut r)).unwrap()).set_min(
        (carry as f64 - (unsafe { floor(carry as f64 / 60 as i32 as f64) }) * 60 as i32 as f64)
            as u32,
    );
    carry = (unsafe { floor(carry as f64 / 60 as i32 as f64) }) as i64;
    carry += (*(borrow(&d)).unwrap()).hour() as i64;
    (*(borrow_mut(&mut r)).unwrap()).set_hour(
        (carry as f64 - (unsafe { floor(carry as f64 / 24 as i32 as f64) }) * 24 as i32 as f64)
            as u32,
    );
    carry = (unsafe { floor(carry as f64 / 24 as i32 as f64) }) as i64;
    if (*(borrow(&r)).unwrap()).year != 0 as i32 as i64
        && ((*(borrow(&r)).unwrap()).mon() as i32 >= 1 as i32
            && (*(borrow(&r)).unwrap()).mon() as i32 <= 12 as i32)
        && (*(borrow(&d)).unwrap()).day()
            > (if (*(borrow(&r)).unwrap()).year % 4 as i32 as i64 == 0 as i32 as i64
                && (*(borrow(&r)).unwrap()).year % 100 as i32 as i64 != 0 as i32 as i64
                || (*(borrow(&r)).unwrap()).year % 400 as i32 as i64 == 0 as i32 as i64
            {
                unsafe {
                    daysInMonthLeap[((*(borrow(&r)).unwrap()).mon() as i32 - 1 as i32) as usize]
                }
            } else {
                unsafe {
                    daysInMonth[((*(borrow(&r)).unwrap()).mon() as i32 - 1 as i32) as usize]
                }
            })
    {
        tempdays = (if (*(borrow(&r)).unwrap()).year % 4 as i32 as i64 == 0 as i32 as i64
            && (*(borrow(&r)).unwrap()).year % 100 as i32 as i64 != 0 as i32 as i64
            || (*(borrow(&r)).unwrap()).year % 400 as i32 as i64 == 0 as i32 as i64
        {
            unsafe {
                daysInMonthLeap[((*(borrow(&r)).unwrap()).mon() as i32 - 1 as i32) as usize]
            }
        } else {
            unsafe { daysInMonth[((*(borrow(&r)).unwrap()).mon() as i32 - 1 as i32) as usize] }
        }) as i64;
    } else if ((*(borrow(&d)).unwrap()).day() as i32) < 1 as i32 {
        tempdays = 1 as i32 as i64;
    } else {
        tempdays = (*(borrow(&d)).unwrap()).day() as i64;
    }
    tempdays += (*(borrow(&u)).unwrap()).day + carry;
    loop {
        if tempdays < 1 as i32 as i64 {
            let mut tmon: i64 = (((*(borrow(&r)).unwrap()).mon() as i32 - 1 as i32 - 1 as i32)
                as f64
                - (unsafe {
                    floor(
                        ((*(borrow(&r)).unwrap()).mon() as i32 - 1 as i32 - 1 as i32) as f64
                            / (13 as i32 - 1 as i32) as f64,
                    )
                }) * (13 as i32 - 1 as i32) as f64
                + 1 as i32 as f64) as i64;
            let mut tyr: i64 = (*(borrow(&r)).unwrap()).year
                + (unsafe {
                    floor(
                        ((*(borrow(&r)).unwrap()).mon() as i32 - 1 as i32 - 1 as i32) as f64
                            / (13 as i32 - 1 as i32) as f64,
                    )
                }) as i64;
            if tyr == 0 as i32 as i64 {
                tyr -= 1;
            }
            if tmon < 1 as i32 as i64 {
                tmon = 1 as i32 as i64;
            }
            if tmon > 12 as i32 as i64 {
                tmon = 12 as i32 as i64;
            }
            tempdays += (if tyr % 4 as i32 as i64 == 0 as i32 as i64
                && tyr % 100 as i32 as i64 != 0 as i32 as i64
                || tyr % 400 as i32 as i64 == 0 as i32 as i64
            {
                unsafe { daysInMonthLeap[(tmon - 1 as i32 as i64) as usize] }
            } else {
                unsafe { daysInMonth[(tmon - 1 as i32 as i64) as usize] }
            }) as i64;
            carry = -(1 as i32) as i64;
        } else {
            if !((*(borrow(&r)).unwrap()).year != 0 as i32 as i64
                && ((*(borrow(&r)).unwrap()).mon() as i32 >= 1 as i32
                    && (*(borrow(&r)).unwrap()).mon() as i32 <= 12 as i32)
                && tempdays
                    > (if (*(borrow(&r)).unwrap()).year % 4 as i32 as i64 == 0 as i32 as i64
                        && (*(borrow(&r)).unwrap()).year % 100 as i32 as i64 != 0 as i32 as i64
                        || (*(borrow(&r)).unwrap()).year % 400 as i32 as i64 == 0 as i32 as i64
                    {
                        unsafe {
                            daysInMonthLeap
                                [((*(borrow(&r)).unwrap()).mon() as i32 - 1 as i32) as usize]
                        }
                    } else {
                        unsafe {
                            daysInMonth[((*(borrow(&r)).unwrap()).mon() as i32 - 1 as i32) as usize]
                        }
                    }) as i64)
            {
                break;
            }
            tempdays = tempdays
                - (if (*(borrow(&r)).unwrap()).year % 4 as i32 as i64 == 0 as i32 as i64
                    && (*(borrow(&r)).unwrap()).year % 100 as i32 as i64 != 0 as i32 as i64
                    || (*(borrow(&r)).unwrap()).year % 400 as i32 as i64 == 0 as i32 as i64
                {
                    unsafe {
                        daysInMonthLeap[((*(borrow(&r)).unwrap()).mon() as i32 - 1 as i32) as usize]
                    }
                } else {
                    unsafe {
                        daysInMonth[((*(borrow(&r)).unwrap()).mon() as i32 - 1 as i32) as usize]
                    }
                }) as i64;
            carry = 1 as i32 as i64;
        }
        temp = (*(borrow(&r)).unwrap()).mon() as i64 + carry;
        (*(borrow_mut(&mut r)).unwrap()).set_mon(
            ((temp - 1 as i32 as i64) as f64
                - (unsafe {
                    floor((temp - 1 as i32 as i64) as f64 / (13 as i32 - 1 as i32) as f64)
                }) * (13 as i32 - 1 as i32) as f64
                + 1 as i32 as f64) as u32,
        );
        (*(borrow_mut(&mut r)).unwrap()).year = (*(borrow(&r)).unwrap()).year
            + (unsafe { floor((temp - 1 as i32 as i64) as f64 / (13 as i32 - 1 as i32) as f64) })
                as i64;
        if (*(borrow(&r)).unwrap()).year == 0 as i32 as i64 {
            if temp < 1 as i32 as i64 {
                let fresh84 = &mut ((*(borrow_mut(&mut r)).unwrap()).year);
                *fresh84 -= 1;
            } else {
                let fresh85 = &mut ((*(borrow_mut(&mut r)).unwrap()).year);
                *fresh85 += 1;
            }
        }
    }
    (*(borrow_mut(&mut r)).unwrap()).set_day(tempdays as u32);
    if (unsafe { (*ret).type_0 }) as u32 != XML_SCHEMAS_DATETIME as i32 as u32 {
        if (*(borrow(&r)).unwrap()).hour() as i32 != 0
            || (*(borrow(&r)).unwrap()).min() as i32 != 0
            || (*(borrow(&r)).unwrap()).sec != 0.
        {
            (unsafe { (*ret).type_0 = XML_SCHEMAS_DATETIME });
        } else if (unsafe { (*ret).type_0 }) as u32 != XML_SCHEMAS_DATE as i32 as u32 {
            if (*(borrow(&r)).unwrap()).mon() as i32 != 1 as i32
                && (*(borrow(&r)).unwrap()).day() as i32 != 1 as i32
            {
                (unsafe { (*ret).type_0 = XML_SCHEMAS_DATE });
            } else if (unsafe { (*ret).type_0 }) as u32 != XML_SCHEMAS_GYEARMONTH as i32 as u32
                && (*(borrow(&r)).unwrap()).mon() as i32 != 1 as i32
            {
                (unsafe { (*ret).type_0 = XML_SCHEMAS_GYEARMONTH });
            }
        }
    }
    xmlSchemaFreeValue(tmp);
    return ret;
}
extern "C" fn xmlSchemaDateNormalize(
    mut dt: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut offset: f64,
) -> *mut crate::src::xmlschemastypes::_xmlSchemaVal {
    let mut dur: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    let mut ret: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    if dt.is_null() {
        return 0 as xmlSchemaValPtr;
    }
    if (unsafe { (*dt).type_0 }) as u32 != XML_SCHEMAS_TIME as i32 as u32
        && (unsafe { (*dt).type_0 }) as u32 != XML_SCHEMAS_DATETIME as i32 as u32
        && (unsafe { (*dt).type_0 }) as u32 != XML_SCHEMAS_DATE as i32 as u32
        || (unsafe { ((*dt).value.date).tzo() }) == 0 as i32
    {
        return xmlSchemaDupVal(dt);
    }
    dur = xmlSchemaNewValue(XML_SCHEMAS_DURATION);
    if dur.is_null() {
        return 0 as xmlSchemaValPtr;
    }
    (unsafe { (*dur).value.date.sec -= offset });
    ret = _xmlSchemaDateAdd(dt, dur);
    if ret.is_null() {
        return 0 as xmlSchemaValPtr;
    }
    xmlSchemaFreeValue(dur);
    return ret;
}
extern "C" fn _xmlSchemaDateCastYMToDays(
    dt: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> i64 {
    let mut ret: i64 = 0;
    let mut mon: i32 = 0;
    mon = (unsafe { ((*dt).value.date).mon() }) as i32;
    if mon <= 0 as i32 {
        mon = 1 as i32;
    }
    if (unsafe { (*dt).value.date.year }) <= 0 as i32 as i64 {
        ret = (unsafe { (*dt).value.date.year }) * 365 as i32 as i64
            + (((unsafe { (*dt).value.date.year }) + 1 as i32 as i64) / 4 as i32 as i64
                - ((unsafe { (*dt).value.date.year }) + 1 as i32 as i64) / 100 as i32 as i64
                + ((unsafe { (*dt).value.date.year }) + 1 as i32 as i64) / 400 as i32 as i64)
            + ((if (unsafe { (*dt).value.date.year }) % 4 as i32 as i64 == 0 as i32 as i64
                && (unsafe { (*dt).value.date.year }) % 100 as i32 as i64 != 0 as i32 as i64
                || (unsafe { (*dt).value.date.year }) % 400 as i32 as i64 == 0 as i32 as i64
            {
                unsafe { dayInLeapYearByMonth[(mon - 1 as i32) as usize] }
            } else {
                unsafe { dayInYearByMonth[(mon - 1 as i32) as usize] }
            }) + 0 as i32 as i64);
    } else {
        ret = ((unsafe { (*dt).value.date.year }) - 1 as i32 as i64) * 365 as i32 as i64
            + (((unsafe { (*dt).value.date.year }) - 1 as i32 as i64) / 4 as i32 as i64
                - ((unsafe { (*dt).value.date.year }) - 1 as i32 as i64) / 100 as i32 as i64
                + ((unsafe { (*dt).value.date.year }) - 1 as i32 as i64) / 400 as i32 as i64)
            + ((if (unsafe { (*dt).value.date.year }) % 4 as i32 as i64 == 0 as i32 as i64
                && (unsafe { (*dt).value.date.year }) % 100 as i32 as i64 != 0 as i32 as i64
                || (unsafe { (*dt).value.date.year }) % 400 as i32 as i64 == 0 as i32 as i64
            {
                unsafe { dayInLeapYearByMonth[(mon - 1 as i32) as usize] }
            } else {
                unsafe { dayInYearByMonth[(mon - 1 as i32) as usize] }
            }) + 0 as i32 as i64);
    }
    return ret;
}
extern "C" fn xmlSchemaCompareDates(
    mut x: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut y: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> i32 {
    let mut xmask: u8 = 0;
    let mut ymask: u8 = 0;
    let mut xor_mask: u8 = 0;
    let mut and_mask: u8 = 0;
    let mut p1: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    let mut p2: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    let mut q1: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    let mut q2: *mut crate::src::xmlschemastypes::_xmlSchemaVal = 0 as *mut xmlSchemaVal;
    let mut p1d: i64 = 0;
    let mut p2d: i64 = 0;
    let mut q1d: i64 = 0;
    let mut q2d: i64 = 0;
    if x.is_null() || y.is_null() {
        return -(2 as i32);
    }
    if (unsafe { (*x).value.date.year }) > 9223372036854775807 as i64 / 366 as i32 as i64
        || (unsafe { (*x).value.date.year })
            < (-(9223372036854775807 as i64) - 1 as i64) / 366 as i32 as i64
        || (unsafe { (*y).value.date.year }) > 9223372036854775807 as i64 / 366 as i32 as i64
        || (unsafe { (*y).value.date.year })
            < (-(9223372036854775807 as i64) - 1 as i64) / 366 as i32 as i64
    {
        return -(2 as i32);
    }
    if (unsafe { ((*x).value.date).tz_flag() }) != 0 {
        if (unsafe { ((*y).value.date).tz_flag() }) == 0 {
            p1 = xmlSchemaDateNormalize(x, 0 as i32 as f64);
            p1d = _xmlSchemaDateCastYMToDays(p1) + (unsafe { ((*p1).value.date).day() }) as i64;
            q1 = xmlSchemaDateNormalize(y, (14 as i32 * (60 as i32 * 60 as i32)) as f64);
            q1d = _xmlSchemaDateCastYMToDays(q1) + (unsafe { ((*q1).value.date).day() }) as i64;
            if p1d < q1d {
                xmlSchemaFreeValue(p1);
                xmlSchemaFreeValue(q1);
                return -(1 as i32);
            } else {
                if p1d == q1d {
                    let mut sec: f64 = 0.;
                    sec = ((unsafe { ((*p1).value.date).hour() }) as i32 * (60 as i32 * 60 as i32)
                        + (unsafe { ((*p1).value.date).min() }) as i32 * 60 as i32
                        + (unsafe { ((*p1).value.date).tzo() }) * 60 as i32)
                        as f64
                        + (unsafe { (*p1).value.date.sec })
                        - (((unsafe { ((*q1).value.date).hour() }) as i32 * (60 as i32 * 60 as i32)
                            + (unsafe { ((*q1).value.date).min() }) as i32 * 60 as i32
                            + (unsafe { ((*q1).value.date).tzo() }) * 60 as i32)
                            as f64
                            + (unsafe { (*q1).value.date.sec }));
                    if sec < 0.0f64 {
                        xmlSchemaFreeValue(p1);
                        xmlSchemaFreeValue(q1);
                        return -(1 as i32);
                    } else {
                        let mut ret: i32 = 0 as i32;
                        q2 = xmlSchemaDateNormalize(
                            y,
                            -(14 as i32 * (60 as i32 * 60 as i32)) as f64,
                        );
                        q2d = _xmlSchemaDateCastYMToDays(q2)
                            + (unsafe { ((*q2).value.date).day() }) as i64;
                        if p1d > q2d {
                            ret = 1 as i32;
                        } else if p1d == q2d {
                            sec = ((unsafe { ((*p1).value.date).hour() }) as i32
                                * (60 as i32 * 60 as i32)
                                + (unsafe { ((*p1).value.date).min() }) as i32 * 60 as i32
                                + (unsafe { ((*p1).value.date).tzo() }) * 60 as i32)
                                as f64
                                + (unsafe { (*p1).value.date.sec })
                                - (((unsafe { ((*q2).value.date).hour() }) as i32
                                    * (60 as i32 * 60 as i32)
                                    + (unsafe { ((*q2).value.date).min() }) as i32 * 60 as i32
                                    + (unsafe { ((*q2).value.date).tzo() }) * 60 as i32)
                                    as f64
                                    + (unsafe { (*q2).value.date.sec }));
                            if sec > 0.0f64 {
                                ret = 1 as i32;
                            } else {
                                ret = 2 as i32;
                            }
                        }
                        xmlSchemaFreeValue(p1);
                        xmlSchemaFreeValue(q1);
                        xmlSchemaFreeValue(q2);
                        if ret != 0 as i32 {
                            return ret;
                        }
                    }
                } else {
                    xmlSchemaFreeValue(p1);
                    xmlSchemaFreeValue(q1);
                }
            }
        }
    } else if (unsafe { ((*y).value.date).tz_flag() }) != 0 {
        q1 = xmlSchemaDateNormalize(y, 0 as i32 as f64);
        q1d = _xmlSchemaDateCastYMToDays(q1) + (unsafe { ((*q1).value.date).day() }) as i64;
        p1 = xmlSchemaDateNormalize(x, -(14 as i32 * (60 as i32 * 60 as i32)) as f64);
        p1d = _xmlSchemaDateCastYMToDays(p1) + (unsafe { ((*p1).value.date).day() }) as i64;
        if p1d < q1d {
            xmlSchemaFreeValue(p1);
            xmlSchemaFreeValue(q1);
            return -(1 as i32);
        } else {
            if p1d == q1d {
                let mut sec_0: f64 = 0.;
                sec_0 = ((unsafe { ((*p1).value.date).hour() }) as i32 * (60 as i32 * 60 as i32)
                    + (unsafe { ((*p1).value.date).min() }) as i32 * 60 as i32
                    + (unsafe { ((*p1).value.date).tzo() }) * 60 as i32)
                    as f64
                    + (unsafe { (*p1).value.date.sec })
                    - (((unsafe { ((*q1).value.date).hour() }) as i32 * (60 as i32 * 60 as i32)
                        + (unsafe { ((*q1).value.date).min() }) as i32 * 60 as i32
                        + (unsafe { ((*q1).value.date).tzo() }) * 60 as i32)
                        as f64
                        + (unsafe { (*q1).value.date.sec }));
                if sec_0 < 0.0f64 {
                    xmlSchemaFreeValue(p1);
                    xmlSchemaFreeValue(q1);
                    return -(1 as i32);
                } else {
                    let mut ret_0: i32 = 0 as i32;
                    p2 = xmlSchemaDateNormalize(x, (14 as i32 * (60 as i32 * 60 as i32)) as f64);
                    p2d = _xmlSchemaDateCastYMToDays(p2)
                        + (unsafe { ((*p2).value.date).day() }) as i64;
                    if p2d > q1d {
                        ret_0 = 1 as i32;
                    } else if p2d == q1d {
                        sec_0 = ((unsafe { ((*p2).value.date).hour() }) as i32
                            * (60 as i32 * 60 as i32)
                            + (unsafe { ((*p2).value.date).min() }) as i32 * 60 as i32
                            + (unsafe { ((*p2).value.date).tzo() }) * 60 as i32)
                            as f64
                            + (unsafe { (*p2).value.date.sec })
                            - (((unsafe { ((*q1).value.date).hour() }) as i32
                                * (60 as i32 * 60 as i32)
                                + (unsafe { ((*q1).value.date).min() }) as i32 * 60 as i32
                                + (unsafe { ((*q1).value.date).tzo() }) * 60 as i32)
                                as f64
                                + (unsafe { (*q1).value.date.sec }));
                        if sec_0 > 0.0f64 {
                            ret_0 = 1 as i32;
                        } else {
                            ret_0 = 2 as i32;
                        }
                    }
                    xmlSchemaFreeValue(p1);
                    xmlSchemaFreeValue(q1);
                    xmlSchemaFreeValue(p2);
                    if ret_0 != 0 as i32 {
                        return ret_0;
                    }
                }
            } else {
                xmlSchemaFreeValue(p1);
                xmlSchemaFreeValue(q1);
            }
        }
    }
    if (unsafe { (*x).type_0 }) as u32 == (unsafe { (*y).type_0 }) as u32 {
        let mut ret_1: i32 = 0 as i32;
        q1 = xmlSchemaDateNormalize(y, 0 as i32 as f64);
        q1d = _xmlSchemaDateCastYMToDays(q1) + (unsafe { ((*q1).value.date).day() }) as i64;
        p1 = xmlSchemaDateNormalize(x, 0 as i32 as f64);
        p1d = _xmlSchemaDateCastYMToDays(p1) + (unsafe { ((*p1).value.date).day() }) as i64;
        if p1d < q1d {
            ret_1 = -(1 as i32);
        } else if p1d > q1d {
            ret_1 = 1 as i32;
        } else {
            let mut sec_1: f64 = 0.;
            sec_1 = ((unsafe { ((*p1).value.date).hour() }) as i32 * (60 as i32 * 60 as i32)
                + (unsafe { ((*p1).value.date).min() }) as i32 * 60 as i32
                + (unsafe { ((*p1).value.date).tzo() }) * 60 as i32) as f64
                + (unsafe { (*p1).value.date.sec })
                - (((unsafe { ((*q1).value.date).hour() }) as i32 * (60 as i32 * 60 as i32)
                    + (unsafe { ((*q1).value.date).min() }) as i32 * 60 as i32
                    + (unsafe { ((*q1).value.date).tzo() }) * 60 as i32) as f64
                    + (unsafe { (*q1).value.date.sec }));
            if sec_1 < 0.0f64 {
                ret_1 = -(1 as i32);
            } else if sec_1 > 0.0f64 {
                ret_1 = 1 as i32;
            }
        }
        xmlSchemaFreeValue(p1);
        xmlSchemaFreeValue(q1);
        return ret_1;
    }
    match (unsafe { (*x).type_0 }) as u32 {
        11 => {
            xmask = 0xf as i32 as u8;
        }
        10 => {
            xmask = 0x7 as i32 as u8;
        }
        8 => {
            xmask = 0x1 as i32 as u8;
        }
        6 => {
            xmask = 0x2 as i32 as u8;
        }
        5 => {
            xmask = 0x3 as i32 as u8;
        }
        9 => {
            xmask = 0x3 as i32 as u8;
        }
        7 => {
            xmask = 0x6 as i32 as u8;
        }
        4 => {
            xmask = 0x8 as i32 as u8;
        }
        _ => {
            xmask = 0 as i32 as u8;
        }
    }
    match (unsafe { (*y).type_0 }) as u32 {
        11 => {
            ymask = 0xf as i32 as u8;
        }
        10 => {
            ymask = 0x7 as i32 as u8;
        }
        8 => {
            ymask = 0x1 as i32 as u8;
        }
        6 => {
            ymask = 0x2 as i32 as u8;
        }
        5 => {
            ymask = 0x3 as i32 as u8;
        }
        9 => {
            ymask = 0x3 as i32 as u8;
        }
        7 => {
            ymask = 0x6 as i32 as u8;
        }
        4 => {
            ymask = 0x8 as i32 as u8;
        }
        _ => {
            ymask = 0 as i32 as u8;
        }
    }
    xor_mask = (xmask as i32 ^ ymask as i32) as u8;
    and_mask = (xmask as i32 & ymask as i32) as u8;
    if xor_mask as i32 & 1 as i32 != 0 {
        return 2 as i32;
    } else {
        if and_mask as i32 & 1 as i32 != 0 {
            if (unsafe { (*x).value.date.year }) < (unsafe { (*y).value.date.year }) {
                return -(1 as i32);
            } else {
                if (unsafe { (*x).value.date.year }) > (unsafe { (*y).value.date.year }) {
                    return 1 as i32;
                }
            }
        }
    }
    if xor_mask as i32 & 2 as i32 != 0 {
        return 2 as i32;
    } else {
        if and_mask as i32 & 2 as i32 != 0 {
            if ((unsafe { ((*x).value.date).mon() }) as i32)
                < (unsafe { ((*y).value.date).mon() }) as i32
            {
                return -(1 as i32);
            } else {
                if (unsafe { ((*x).value.date).mon() }) as i32
                    > (unsafe { ((*y).value.date).mon() }) as i32
                {
                    return 1 as i32;
                }
            }
        }
    }
    if xor_mask as i32 & 4 as i32 != 0 {
        return 2 as i32;
    } else {
        if and_mask as i32 & 4 as i32 != 0 {
            if ((unsafe { ((*x).value.date).day() }) as i32)
                < (unsafe { ((*y).value.date).day() }) as i32
            {
                return -(1 as i32);
            } else {
                if (unsafe { ((*x).value.date).day() }) as i32
                    > (unsafe { ((*y).value.date).day() }) as i32
                {
                    return 1 as i32;
                }
            }
        }
    }
    if xor_mask as i32 & 8 as i32 != 0 {
        return 2 as i32;
    } else {
        if and_mask as i32 & 8 as i32 != 0 {
            if ((unsafe { ((*x).value.date).hour() }) as i32)
                < (unsafe { ((*y).value.date).hour() }) as i32
            {
                return -(1 as i32);
            } else {
                if (unsafe { ((*x).value.date).hour() }) as i32
                    > (unsafe { ((*y).value.date).hour() }) as i32
                {
                    return 1 as i32;
                } else {
                    if ((unsafe { ((*x).value.date).min() }) as i32)
                        < (unsafe { ((*y).value.date).min() }) as i32
                    {
                        return -(1 as i32);
                    } else {
                        if (unsafe { ((*x).value.date).min() }) as i32
                            > (unsafe { ((*y).value.date).min() }) as i32
                        {
                            return 1 as i32;
                        } else {
                            if (unsafe { (*x).value.date.sec }) < (unsafe { (*y).value.date.sec }) {
                                return -(1 as i32);
                            } else {
                                if (unsafe { (*x).value.date.sec })
                                    > (unsafe { (*y).value.date.sec })
                                {
                                    return 1 as i32;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return 0 as i32;
}
extern "C" fn xmlSchemaComparePreserveReplaceStrings(
    mut x: *const u8,
    mut y: *const u8,
    mut invert: i32,
) -> i32 {
    let mut tmp: i32 = 0;
    while (unsafe { *x }) as i32 != 0 as i32 && (unsafe { *y }) as i32 != 0 as i32 {
        if (unsafe { *y }) as i32 == 0x9 as i32
            || (unsafe { *y }) as i32 == 0xa as i32
            || (unsafe { *y }) as i32 == 0xd as i32
        {
            if !((unsafe { *x }) as i32 == 0x20 as i32) {
                if ((unsafe { *x }) as i32 - 0x20 as i32) < 0 as i32 {
                    if invert != 0 {
                        return 1 as i32;
                    } else {
                        return -(1 as i32);
                    }
                } else if invert != 0 {
                    return -(1 as i32);
                } else {
                    return 1 as i32;
                }
            }
        } else {
            tmp = (unsafe { *x }) as i32 - (unsafe { *y }) as i32;
            if tmp < 0 as i32 {
                if invert != 0 {
                    return 1 as i32;
                } else {
                    return -(1 as i32);
                }
            }
            if tmp > 0 as i32 {
                if invert != 0 {
                    return -(1 as i32);
                } else {
                    return 1 as i32;
                }
            }
        }
        x = unsafe { x.offset(1) };
        y = unsafe { y.offset(1) };
    }
    if (unsafe { *x }) as i32 != 0 as i32 {
        if invert != 0 {
            return -(1 as i32);
        } else {
            return 1 as i32;
        }
    }
    if (unsafe { *y }) as i32 != 0 as i32 {
        if invert != 0 {
            return 1 as i32;
        } else {
            return -(1 as i32);
        }
    }
    return 0 as i32;
}
extern "C" fn xmlSchemaComparePreserveCollapseStrings(
    mut x: *const u8,
    mut y: *const u8,
    mut invert: i32,
) -> i32 {
    let mut tmp: i32 = 0;
    while (unsafe { *y }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *y }) as i32 && (unsafe { *y }) as i32 <= 0xa as i32
        || (unsafe { *y }) as i32 == 0xd as i32
    {
        y = unsafe { y.offset(1) };
    }
    while (unsafe { *x }) as i32 != 0 as i32 && (unsafe { *y }) as i32 != 0 as i32 {
        if (unsafe { *y }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *y }) as i32 && (unsafe { *y }) as i32 <= 0xa as i32
            || (unsafe { *y }) as i32 == 0xd as i32
        {
            if !((unsafe { *x }) as i32 == 0x20 as i32) {
                if ((unsafe { *x }) as i32 - 0x20 as i32) < 0 as i32 {
                    if invert != 0 {
                        return 1 as i32;
                    } else {
                        return -(1 as i32);
                    }
                } else if invert != 0 {
                    return -(1 as i32);
                } else {
                    return 1 as i32;
                }
            }
            x = unsafe { x.offset(1) };
            y = unsafe { y.offset(1) };
            while (unsafe { *y }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *y }) as i32 && (unsafe { *y }) as i32 <= 0xa as i32
                || (unsafe { *y }) as i32 == 0xd as i32
            {
                y = unsafe { y.offset(1) };
            }
        } else {
            let mut fresh86 = x;
            x = unsafe { x.offset(1) };
            let mut fresh87 = y;
            y = unsafe { y.offset(1) };
            tmp = (unsafe { *fresh86 }) as i32 - (unsafe { *fresh87 }) as i32;
            if tmp < 0 as i32 {
                if invert != 0 {
                    return 1 as i32;
                } else {
                    return -(1 as i32);
                }
            }
            if tmp > 0 as i32 {
                if invert != 0 {
                    return -(1 as i32);
                } else {
                    return 1 as i32;
                }
            }
        }
    }
    if (unsafe { *x }) as i32 != 0 as i32 {
        if invert != 0 {
            return -(1 as i32);
        } else {
            return 1 as i32;
        }
    }
    if (unsafe { *y }) as i32 != 0 as i32 {
        while (unsafe { *y }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *y }) as i32 && (unsafe { *y }) as i32 <= 0xa as i32
            || (unsafe { *y }) as i32 == 0xd as i32
        {
            y = unsafe { y.offset(1) };
        }
        if (unsafe { *y }) as i32 != 0 as i32 {
            if invert != 0 {
                return 1 as i32;
            } else {
                return -(1 as i32);
            }
        }
    }
    return 0 as i32;
}
extern "C" fn xmlSchemaCompareReplaceCollapseStrings(
    mut x: *const u8,
    mut y: *const u8,
    mut invert: i32,
) -> i32 {
    let mut tmp: i32 = 0;
    while (unsafe { *y }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *y }) as i32 && (unsafe { *y }) as i32 <= 0xa as i32
        || (unsafe { *y }) as i32 == 0xd as i32
    {
        y = unsafe { y.offset(1) };
    }
    while (unsafe { *x }) as i32 != 0 as i32 && (unsafe { *y }) as i32 != 0 as i32 {
        if (unsafe { *y }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *y }) as i32 && (unsafe { *y }) as i32 <= 0xa as i32
            || (unsafe { *y }) as i32 == 0xd as i32
        {
            if !((unsafe { *x }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *x }) as i32 && (unsafe { *x }) as i32 <= 0xa as i32
                || (unsafe { *x }) as i32 == 0xd as i32)
            {
                if ((unsafe { *x }) as i32 - 0x20 as i32) < 0 as i32 {
                    if invert != 0 {
                        return 1 as i32;
                    } else {
                        return -(1 as i32);
                    }
                } else if invert != 0 {
                    return -(1 as i32);
                } else {
                    return 1 as i32;
                }
            }
            x = unsafe { x.offset(1) };
            y = unsafe { y.offset(1) };
            while (unsafe { *y }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *y }) as i32 && (unsafe { *y }) as i32 <= 0xa as i32
                || (unsafe { *y }) as i32 == 0xd as i32
            {
                y = unsafe { y.offset(1) };
            }
        } else {
            if (unsafe { *x }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *x }) as i32 && (unsafe { *x }) as i32 <= 0xa as i32
                || (unsafe { *x }) as i32 == 0xd as i32
            {
                if (0x20 as i32 - (unsafe { *y }) as i32) < 0 as i32 {
                    if invert != 0 {
                        return 1 as i32;
                    } else {
                        return -(1 as i32);
                    }
                } else if invert != 0 {
                    return -(1 as i32);
                } else {
                    return 1 as i32;
                }
            }
            let mut fresh88 = x;
            x = unsafe { x.offset(1) };
            let mut fresh89 = y;
            y = unsafe { y.offset(1) };
            tmp = (unsafe { *fresh88 }) as i32 - (unsafe { *fresh89 }) as i32;
            if tmp < 0 as i32 {
                return -(1 as i32);
            }
            if tmp > 0 as i32 {
                return 1 as i32;
            }
        }
    }
    if (unsafe { *x }) as i32 != 0 as i32 {
        if invert != 0 {
            return -(1 as i32);
        } else {
            return 1 as i32;
        }
    }
    if (unsafe { *y }) as i32 != 0 as i32 {
        while (unsafe { *y }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *y }) as i32 && (unsafe { *y }) as i32 <= 0xa as i32
            || (unsafe { *y }) as i32 == 0xd as i32
        {
            y = unsafe { y.offset(1) };
        }
        if (unsafe { *y }) as i32 != 0 as i32 {
            if invert != 0 {
                return 1 as i32;
            } else {
                return -(1 as i32);
            }
        }
    }
    return 0 as i32;
}
extern "C" fn xmlSchemaCompareReplacedStrings(mut x: *const u8, mut y: *const u8) -> i32 {
    let mut tmp: i32 = 0;
    while (unsafe { *x }) as i32 != 0 as i32 && (unsafe { *y }) as i32 != 0 as i32 {
        if (unsafe { *y }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *y }) as i32 && (unsafe { *y }) as i32 <= 0xa as i32
            || (unsafe { *y }) as i32 == 0xd as i32
        {
            if !((unsafe { *x }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *x }) as i32 && (unsafe { *x }) as i32 <= 0xa as i32
                || (unsafe { *x }) as i32 == 0xd as i32)
            {
                if ((unsafe { *x }) as i32 - 0x20 as i32) < 0 as i32 {
                    return -(1 as i32);
                } else {
                    return 1 as i32;
                }
            }
        } else {
            if (unsafe { *x }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *x }) as i32 && (unsafe { *x }) as i32 <= 0xa as i32
                || (unsafe { *x }) as i32 == 0xd as i32
            {
                if (0x20 as i32 - (unsafe { *y }) as i32) < 0 as i32 {
                    return -(1 as i32);
                } else {
                    return 1 as i32;
                }
            }
            tmp = (unsafe { *x }) as i32 - (unsafe { *y }) as i32;
            if tmp < 0 as i32 {
                return -(1 as i32);
            }
            if tmp > 0 as i32 {
                return 1 as i32;
            }
        }
        x = unsafe { x.offset(1) };
        y = unsafe { y.offset(1) };
    }
    if (unsafe { *x }) as i32 != 0 as i32 {
        return 1 as i32;
    }
    if (unsafe { *y }) as i32 != 0 as i32 {
        return -(1 as i32);
    }
    return 0 as i32;
}
extern "C" fn xmlSchemaCompareNormStrings(mut x: *const u8, mut y: *const u8) -> i32 {
    let mut tmp: i32 = 0;
    while (unsafe { *x }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *x }) as i32 && (unsafe { *x }) as i32 <= 0xa as i32
        || (unsafe { *x }) as i32 == 0xd as i32
    {
        x = unsafe { x.offset(1) };
    }
    while (unsafe { *y }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *y }) as i32 && (unsafe { *y }) as i32 <= 0xa as i32
        || (unsafe { *y }) as i32 == 0xd as i32
    {
        y = unsafe { y.offset(1) };
    }
    while (unsafe { *x }) as i32 != 0 as i32 && (unsafe { *y }) as i32 != 0 as i32 {
        if (unsafe { *x }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *x }) as i32 && (unsafe { *x }) as i32 <= 0xa as i32
            || (unsafe { *x }) as i32 == 0xd as i32
        {
            if !((unsafe { *y }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *y }) as i32 && (unsafe { *y }) as i32 <= 0xa as i32
                || (unsafe { *y }) as i32 == 0xd as i32)
            {
                tmp = (unsafe { *x }) as i32 - (unsafe { *y }) as i32;
                return tmp;
            }
            while (unsafe { *x }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *x }) as i32 && (unsafe { *x }) as i32 <= 0xa as i32
                || (unsafe { *x }) as i32 == 0xd as i32
            {
                x = unsafe { x.offset(1) };
            }
            while (unsafe { *y }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *y }) as i32 && (unsafe { *y }) as i32 <= 0xa as i32
                || (unsafe { *y }) as i32 == 0xd as i32
            {
                y = unsafe { y.offset(1) };
            }
        } else {
            let mut fresh90 = x;
            x = unsafe { x.offset(1) };
            let mut fresh91 = y;
            y = unsafe { y.offset(1) };
            tmp = (unsafe { *fresh90 }) as i32 - (unsafe { *fresh91 }) as i32;
            if tmp < 0 as i32 {
                return -(1 as i32);
            }
            if tmp > 0 as i32 {
                return 1 as i32;
            }
        }
    }
    if (unsafe { *x }) as i32 != 0 as i32 {
        while (unsafe { *x }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *x }) as i32 && (unsafe { *x }) as i32 <= 0xa as i32
            || (unsafe { *x }) as i32 == 0xd as i32
        {
            x = unsafe { x.offset(1) };
        }
        if (unsafe { *x }) as i32 != 0 as i32 {
            return 1 as i32;
        }
    }
    if (unsafe { *y }) as i32 != 0 as i32 {
        while (unsafe { *y }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *y }) as i32 && (unsafe { *y }) as i32 <= 0xa as i32
            || (unsafe { *y }) as i32 == 0xd as i32
        {
            y = unsafe { y.offset(1) };
        }
        if (unsafe { *y }) as i32 != 0 as i32 {
            return -(1 as i32);
        }
    }
    return 0 as i32;
}
extern "C" fn xmlSchemaCompareFloats(
    mut x: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut y: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> i32 {
    let mut d1: f64 = 0.;
    let mut d2: f64 = 0.;
    if x.is_null() || y.is_null() {
        return -(2 as i32);
    }
    if (unsafe { (*x).type_0 }) as u32 == XML_SCHEMAS_DOUBLE as i32 as u32 {
        d1 = unsafe { (*x).value.d };
    } else if (unsafe { (*x).type_0 }) as u32 == XML_SCHEMAS_FLOAT as i32 as u32 {
        d1 = (unsafe { (*x).value.f }) as f64;
    } else {
        return -(2 as i32);
    }
    if (unsafe { (*y).type_0 }) as u32 == XML_SCHEMAS_DOUBLE as i32 as u32 {
        d2 = unsafe { (*y).value.d };
    } else if (unsafe { (*y).type_0 }) as u32 == XML_SCHEMAS_FLOAT as i32 as u32 {
        d2 = (unsafe { (*y).value.f }) as f64;
    } else {
        return -(2 as i32);
    }
    if (unsafe { xmlXPathIsNaN(d1) }) != 0 {
        if (unsafe { xmlXPathIsNaN(d2) }) != 0 {
            return 0 as i32;
        }
        return 1 as i32;
    }
    if (unsafe { xmlXPathIsNaN(d2) }) != 0 {
        return -(1 as i32);
    }
    if d1 == (unsafe { xmlXPathPINF }) {
        if d2 == (unsafe { xmlXPathPINF }) {
            return 0 as i32;
        }
        return 1 as i32;
    }
    if d2 == (unsafe { xmlXPathPINF }) {
        return -(1 as i32);
    }
    if d1 == (unsafe { xmlXPathNINF }) {
        if d2 == (unsafe { xmlXPathNINF }) {
            return 0 as i32;
        }
        return -(1 as i32);
    }
    if d2 == (unsafe { xmlXPathNINF }) {
        return 1 as i32;
    }
    if d1 < d2 {
        return -(1 as i32);
    }
    if d1 > d2 {
        return 1 as i32;
    }
    if d1 == d2 {
        return 0 as i32;
    }
    return 2 as i32;
}
extern "C" fn xmlSchemaCompareValuesInternal(
    mut xtype: u32,
    mut x: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut xvalue: *const u8,
    mut xws: u32,
    mut ytype: u32,
    mut y: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut yvalue: *const u8,
    mut yws: u32,
) -> i32 {
    match xtype as u32 {
        0 | 45 => return -(2 as i32),
        30 | 31 | 32 | 33 | 34 | 35 | 36 | 37 | 38 | 39 | 40 | 41 | 42 | 3 => {
            if x.is_null() || y.is_null() {
                return -(2 as i32);
            }
            if ytype as u32 == xtype as u32 {
                return xmlSchemaCompareDecimals(x, y);
            }
            if ytype as u32 == XML_SCHEMAS_DECIMAL as i32 as u32
                || ytype as u32 == XML_SCHEMAS_INTEGER as i32 as u32
                || ytype as u32 == XML_SCHEMAS_NPINTEGER as i32 as u32
                || ytype as u32 == XML_SCHEMAS_NINTEGER as i32 as u32
                || ytype as u32 == XML_SCHEMAS_NNINTEGER as i32 as u32
                || ytype as u32 == XML_SCHEMAS_PINTEGER as i32 as u32
                || ytype as u32 == XML_SCHEMAS_INT as i32 as u32
                || ytype as u32 == XML_SCHEMAS_UINT as i32 as u32
                || ytype as u32 == XML_SCHEMAS_LONG as i32 as u32
                || ytype as u32 == XML_SCHEMAS_ULONG as i32 as u32
                || ytype as u32 == XML_SCHEMAS_SHORT as i32 as u32
                || ytype as u32 == XML_SCHEMAS_USHORT as i32 as u32
                || ytype as u32 == XML_SCHEMAS_BYTE as i32 as u32
                || ytype as u32 == XML_SCHEMAS_UBYTE as i32 as u32
            {
                return xmlSchemaCompareDecimals(x, y);
            }
            return -(2 as i32);
        }
        12 => {
            if x.is_null() || y.is_null() {
                return -(2 as i32);
            }
            if ytype as u32 == XML_SCHEMAS_DURATION as i32 as u32 {
                return xmlSchemaCompareDurations(x, y);
            }
            return -(2 as i32);
        }
        4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 => {
            if x.is_null() || y.is_null() {
                return -(2 as i32);
            }
            if ytype as u32 == XML_SCHEMAS_DATETIME as i32 as u32
                || ytype as u32 == XML_SCHEMAS_TIME as i32 as u32
                || ytype as u32 == XML_SCHEMAS_GDAY as i32 as u32
                || ytype as u32 == XML_SCHEMAS_GMONTH as i32 as u32
                || ytype as u32 == XML_SCHEMAS_GMONTHDAY as i32 as u32
                || ytype as u32 == XML_SCHEMAS_GYEAR as i32 as u32
                || ytype as u32 == XML_SCHEMAS_DATE as i32 as u32
                || ytype as u32 == XML_SCHEMAS_GYEARMONTH as i32 as u32
            {
                return xmlSchemaCompareDates(x, y);
            }
            return -(2 as i32);
        }
        46 | 1 | 2 | 16 | 17 | 18 | 20 | 22 | 23 | 24 | 26 | 29 => {
            let mut xv: *const u8 = 0 as *const xmlChar;
            let mut yv: *const u8 = 0 as *const xmlChar;
            if x.is_null() {
                xv = xvalue;
            } else {
                xv = unsafe { (*x).value.str_0 };
            }
            if y.is_null() {
                yv = yvalue;
            } else {
                yv = unsafe { (*y).value.str_0 };
            }
            if ytype as u32 == XML_SCHEMAS_QNAME as i32 as u32 {
                (unsafe {
                    (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                        b"xmlschemastypes.c\0" as *const u8 as *const i8,
                        4918 as i32,
                    )
                });
                if y.is_null() {
                    return -(2 as i32);
                }
                return -(2 as i32);
            }
            if ytype as u32 == XML_SCHEMAS_ANYSIMPLETYPE as i32 as u32
                || ytype as u32 == XML_SCHEMAS_STRING as i32 as u32
                || ytype as u32 == XML_SCHEMAS_NORMSTRING as i32 as u32
                || ytype as u32 == XML_SCHEMAS_TOKEN as i32 as u32
                || ytype as u32 == XML_SCHEMAS_LANGUAGE as i32 as u32
                || ytype as u32 == XML_SCHEMAS_NMTOKEN as i32 as u32
                || ytype as u32 == XML_SCHEMAS_NAME as i32 as u32
                || ytype as u32 == XML_SCHEMAS_NCNAME as i32 as u32
                || ytype as u32 == XML_SCHEMAS_ID as i32 as u32
                || ytype as u32 == XML_SCHEMAS_IDREF as i32 as u32
                || ytype as u32 == XML_SCHEMAS_ENTITY as i32 as u32
                || ytype as u32 == XML_SCHEMAS_ANYURI as i32 as u32
            {
                if xws as u32 == XML_SCHEMA_WHITESPACE_PRESERVE as i32 as u32 {
                    if yws as u32 == XML_SCHEMA_WHITESPACE_PRESERVE as i32 as u32 {
                        if xmlStrEqual(xv, yv) != 0 {
                            return 0 as i32;
                        } else {
                            return 2 as i32;
                        }
                    } else {
                        if yws as u32 == XML_SCHEMA_WHITESPACE_REPLACE as i32 as u32 {
                            return xmlSchemaComparePreserveReplaceStrings(xv, yv, 0 as i32);
                        } else {
                            if yws as u32 == XML_SCHEMA_WHITESPACE_COLLAPSE as i32 as u32 {
                                return xmlSchemaComparePreserveCollapseStrings(xv, yv, 0 as i32);
                            }
                        }
                    }
                } else if xws as u32 == XML_SCHEMA_WHITESPACE_REPLACE as i32 as u32 {
                    if yws as u32 == XML_SCHEMA_WHITESPACE_PRESERVE as i32 as u32 {
                        return xmlSchemaComparePreserveReplaceStrings(yv, xv, 1 as i32);
                    }
                    if yws as u32 == XML_SCHEMA_WHITESPACE_REPLACE as i32 as u32 {
                        return xmlSchemaCompareReplacedStrings(xv, yv);
                    }
                    if yws as u32 == XML_SCHEMA_WHITESPACE_COLLAPSE as i32 as u32 {
                        return xmlSchemaCompareReplaceCollapseStrings(xv, yv, 0 as i32);
                    }
                } else if xws as u32 == XML_SCHEMA_WHITESPACE_COLLAPSE as i32 as u32 {
                    if yws as u32 == XML_SCHEMA_WHITESPACE_PRESERVE as i32 as u32 {
                        return xmlSchemaComparePreserveCollapseStrings(yv, xv, 1 as i32);
                    }
                    if yws as u32 == XML_SCHEMA_WHITESPACE_REPLACE as i32 as u32 {
                        return xmlSchemaCompareReplaceCollapseStrings(yv, xv, 1 as i32);
                    }
                    if yws as u32 == XML_SCHEMA_WHITESPACE_COLLAPSE as i32 as u32 {
                        return xmlSchemaCompareNormStrings(xv, yv);
                    }
                } else {
                    return -(2 as i32);
                }
            }
            return -(2 as i32);
        }
        21 | 28 => {
            if x.is_null() || y.is_null() {
                return -(2 as i32);
            }
            if ytype as u32 == XML_SCHEMAS_QNAME as i32 as u32
                || ytype as u32 == XML_SCHEMAS_NOTATION as i32 as u32
            {
                if xmlStrEqual(
                    unsafe { (*x).value.qname.name },
                    unsafe { (*y).value.qname.name },
                ) != 0
                    && xmlStrEqual(
                        unsafe { (*x).value.qname.uri },
                        unsafe { (*y).value.qname.uri },
                    ) != 0
                {
                    return 0 as i32;
                }
                return 2 as i32;
            }
            return -(2 as i32);
        }
        13 | 14 => {
            if x.is_null() || y.is_null() {
                return -(2 as i32);
            }
            if ytype as u32 == XML_SCHEMAS_FLOAT as i32 as u32
                || ytype as u32 == XML_SCHEMAS_DOUBLE as i32 as u32
            {
                return xmlSchemaCompareFloats(x, y);
            }
            return -(2 as i32);
        }
        15 => {
            if x.is_null() || y.is_null() {
                return -(2 as i32);
            }
            if ytype as u32 == XML_SCHEMAS_BOOLEAN as i32 as u32 {
                if (unsafe { (*x).value.b }) == (unsafe { (*y).value.b }) {
                    return 0 as i32;
                }
                if (unsafe { (*x).value.b }) == 0 as i32 {
                    return -(1 as i32);
                }
                return 1 as i32;
            }
            return -(2 as i32);
        }
        43 => {
            if x.is_null() || y.is_null() {
                return -(2 as i32);
            }
            if ytype as u32 == XML_SCHEMAS_HEXBINARY as i32 as u32 {
                if (unsafe { (*x).value.hex.total }) == (unsafe { (*y).value.hex.total }) {
                    let mut ret: i32 = xmlStrcmp(
                        unsafe { (*x).value.hex.str_0 },
                        unsafe { (*y).value.hex.str_0 },
                    );
                    if ret > 0 as i32 {
                        return 1 as i32;
                    } else {
                        if ret == 0 as i32 {
                            return 0 as i32;
                        }
                    }
                } else if (unsafe { (*x).value.hex.total }) > (unsafe { (*y).value.hex.total }) {
                    return 1 as i32;
                }
                return -(1 as i32);
            }
            return -(2 as i32);
        }
        44 => {
            if x.is_null() || y.is_null() {
                return -(2 as i32);
            }
            if ytype as u32 == XML_SCHEMAS_BASE64BINARY as i32 as u32 {
                if (unsafe { (*x).value.base64.total }) == (unsafe { (*y).value.base64.total }) {
                    let mut ret_0: i32 = xmlStrcmp(
                        unsafe { (*x).value.base64.str_0 },
                        unsafe { (*y).value.base64.str_0 },
                    );
                    if ret_0 > 0 as i32 {
                        return 1 as i32;
                    } else if ret_0 == 0 as i32 {
                        return 0 as i32;
                    } else {
                        return -(1 as i32);
                    }
                } else if (unsafe { (*x).value.base64.total })
                    > (unsafe { (*y).value.base64.total })
                {
                    return 1 as i32;
                } else {
                    return -(1 as i32);
                }
            }
            return -(2 as i32);
        }
        25 | 27 | 19 => {
            (unsafe {
                (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                    b"xmlschemastypes.c\0" as *const u8 as *const i8,
                    5043 as i32,
                )
            });
        }
        _ => {}
    }
    return -(2 as i32);
}
#[no_mangle]
pub extern "C" fn xmlSchemaCompareValues(
    mut x: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut y: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> i32 {
    let mut xws: u32 = XML_SCHEMA_WHITESPACE_UNKNOWN;
    let mut yws: u32 = XML_SCHEMA_WHITESPACE_UNKNOWN;
    if x.is_null() || y.is_null() {
        return -(2 as i32);
    }
    if (unsafe { (*x).type_0 }) as u32 == XML_SCHEMAS_STRING as i32 as u32 {
        xws = XML_SCHEMA_WHITESPACE_PRESERVE;
    } else if (unsafe { (*x).type_0 }) as u32 == XML_SCHEMAS_NORMSTRING as i32 as u32 {
        xws = XML_SCHEMA_WHITESPACE_REPLACE;
    } else {
        xws = XML_SCHEMA_WHITESPACE_COLLAPSE;
    }
    if (unsafe { (*y).type_0 }) as u32 == XML_SCHEMAS_STRING as i32 as u32 {
        yws = XML_SCHEMA_WHITESPACE_PRESERVE;
    } else if (unsafe { (*y).type_0 }) as u32 == XML_SCHEMAS_NORMSTRING as i32 as u32 {
        yws = XML_SCHEMA_WHITESPACE_REPLACE;
    } else {
        yws = XML_SCHEMA_WHITESPACE_COLLAPSE;
    }
    return xmlSchemaCompareValuesInternal(
        unsafe { (*x).type_0 },
        x,
        0 as *const xmlChar,
        xws,
        unsafe { (*y).type_0 },
        y,
        0 as *const xmlChar,
        yws,
    );
}
#[no_mangle]
pub extern "C" fn xmlSchemaCompareValuesWhtsp(
    mut x: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut xws: u32,
    mut y: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut yws: u32,
) -> i32 {
    if x.is_null() || y.is_null() {
        return -(2 as i32);
    }
    return xmlSchemaCompareValuesInternal(
        unsafe { (*x).type_0 },
        x,
        0 as *const xmlChar,
        xws,
        unsafe { (*y).type_0 },
        y,
        0 as *const xmlChar,
        yws,
    );
}
extern "C" fn xmlSchemaCompareValuesWhtspExt(
    mut xtype: u32,
    mut x: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut xvalue: *const u8,
    mut xws: u32,
    mut ytype: u32,
    mut y: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut yvalue: *const u8,
    mut yws: u32,
) -> i32 {
    return xmlSchemaCompareValuesInternal(xtype, x, xvalue, xws, ytype, y, yvalue, yws);
}
extern "C" fn xmlSchemaNormLen(mut value: *const u8) -> i32 {
    let mut utf: *const u8 = 0 as *const xmlChar;
    let mut ret: i32 = 0 as i32;
    if value.is_null() {
        return -(1 as i32);
    }
    utf = value;
    while (unsafe { *utf }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *utf }) as i32 && (unsafe { *utf }) as i32 <= 0xa as i32
        || (unsafe { *utf }) as i32 == 0xd as i32
    {
        utf = unsafe { utf.offset(1) };
    }
    while (unsafe { *utf }) as i32 != 0 as i32 {
        if (unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0x80 as i32 != 0 {
            if (unsafe { *utf.offset(1 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                return -(1 as i32);
            }
            if (unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0xe0 as i32 == 0xe0 as i32 {
                if (unsafe { *utf.offset(2 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                    return -(1 as i32);
                }
                if (unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0xf0 as i32 == 0xf0 as i32 {
                    if (unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0xf8 as i32
                        != 0xf0 as i32
                        || (unsafe { *utf.offset(3 as i32 as isize) }) as i32 & 0xc0 as i32
                            != 0x80 as i32
                    {
                        return -(1 as i32);
                    }
                    utf = unsafe { utf.offset(4 as i32 as isize) };
                } else {
                    utf = unsafe { utf.offset(3 as i32 as isize) };
                }
            } else {
                utf = unsafe { utf.offset(2 as i32 as isize) };
            }
        } else if (unsafe { *utf }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *utf }) as i32 && (unsafe { *utf }) as i32 <= 0xa as i32
            || (unsafe { *utf }) as i32 == 0xd as i32
        {
            while (unsafe { *utf }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *utf }) as i32 && (unsafe { *utf }) as i32 <= 0xa as i32
                || (unsafe { *utf }) as i32 == 0xd as i32
            {
                utf = unsafe { utf.offset(1) };
            }
            if (unsafe { *utf }) as i32 == 0 as i32 {
                break;
            }
        } else {
            utf = unsafe { utf.offset(1) };
        }
        ret += 1;
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSchemaGetFacetValueAsULong<'a1>(
    mut facet: *mut crate::src::xmlschemas::_xmlSchemaFacet<'a1>,
) -> u64 {
    if facet.is_null() || (unsafe { (*facet).val }).is_null() {
        return 0 as i32 as u64;
    }
    return unsafe { (*(*facet).val).value.decimal.lo };
}
#[no_mangle]
pub extern "C" fn xmlSchemaValidateListSimpleTypeFacet<'a1, 'a2>(
    mut facet: *mut crate::src::xmlschemas::_xmlSchemaFacet<'a1>,
    mut value: *const u8,
    mut actualLen: u64,
    mut expectedLen: Option<&'a2 mut u64>,
) -> i32 {
    if facet.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*facet).type_0 }) as u32 == XML_SCHEMA_FACET_LENGTH as i32 as u32 {
        if actualLen != (unsafe { (*(*facet).val).value.decimal.lo }) {
            if !borrow(&expectedLen).is_none() {
                *(borrow_mut(&mut expectedLen)).unwrap() =
                    unsafe { (*(*facet).val).value.decimal.lo };
            }
            return XML_SCHEMAV_CVC_LENGTH_VALID as i32;
        }
    } else if (unsafe { (*facet).type_0 }) as u32 == XML_SCHEMA_FACET_MINLENGTH as i32 as u32 {
        if actualLen < (unsafe { (*(*facet).val).value.decimal.lo }) {
            if !borrow(&expectedLen).is_none() {
                *(borrow_mut(&mut expectedLen)).unwrap() =
                    unsafe { (*(*facet).val).value.decimal.lo };
            }
            return XML_SCHEMAV_CVC_MINLENGTH_VALID as i32;
        }
    } else if (unsafe { (*facet).type_0 }) as u32 == XML_SCHEMA_FACET_MAXLENGTH as i32 as u32 {
        if actualLen > (unsafe { (*(*facet).val).value.decimal.lo }) {
            if !borrow(&expectedLen).is_none() {
                *(borrow_mut(&mut expectedLen)).unwrap() =
                    unsafe { (*(*facet).val).value.decimal.lo };
            }
            return XML_SCHEMAV_CVC_MAXLENGTH_VALID as i32;
        }
    } else {
        return xmlSchemaValidateFacet(
            Option::<&'_ mut crate::src::xmlschemas::_xmlSchemaType<'_>>::None,
            facet,
            value,
            0 as xmlSchemaValPtr,
        );
    }
    return 0 as i32;
}
extern "C" fn xmlSchemaValidateLengthFacetInternal<'a1, 'a2>(
    mut facet: *mut crate::src::xmlschemas::_xmlSchemaFacet<'a1>,
    mut valType: u32,
    mut value: *const u8,
    mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut length: Option<&'a2 mut u64>,
    mut ws: u32,
) -> i32 {
    let mut len: u32 = 0 as i32 as u32;
    if borrow(&length).is_none() || facet.is_null() {
        return -(1 as i32);
    }
    *(borrow_mut(&mut length)).unwrap() = 0 as i32 as u64;
    if (unsafe { (*facet).type_0 }) as u32 != XML_SCHEMA_FACET_LENGTH as i32 as u32
        && (unsafe { (*facet).type_0 }) as u32 != XML_SCHEMA_FACET_MAXLENGTH as i32 as u32
        && (unsafe { (*facet).type_0 }) as u32 != XML_SCHEMA_FACET_MINLENGTH as i32 as u32
    {
        return -(1 as i32);
    }
    if (unsafe { (*facet).val }).is_null()
        || (unsafe { (*(*facet).val).type_0 }) as u32 != XML_SCHEMAS_DECIMAL as i32 as u32
            && (unsafe { (*(*facet).val).type_0 }) as u32 != XML_SCHEMAS_NNINTEGER as i32 as u32
        || (unsafe { ((*(*facet).val).value.decimal).frac() }) as i32 != 0 as i32
    {
        return -(1 as i32);
    }
    if !val.is_null() && (unsafe { (*val).type_0 }) as u32 == XML_SCHEMAS_HEXBINARY as i32 as u32 {
        len = unsafe { (*val).value.hex.total };
    } else if !val.is_null()
        && (unsafe { (*val).type_0 }) as u32 == XML_SCHEMAS_BASE64BINARY as i32 as u32
    {
        len = unsafe { (*val).value.base64.total };
    } else {
        match valType as u32 {
            1 | 2 => {
                if ws as u32 == XML_SCHEMA_WHITESPACE_UNKNOWN as i32 as u32 {
                    if valType as u32 == XML_SCHEMAS_STRING as i32 as u32 {
                        len = xmlUTF8Strlen(value) as u32;
                    } else {
                        len = xmlSchemaNormLen(value) as u32;
                    }
                } else if !value.is_null() {
                    if ws as u32 == XML_SCHEMA_WHITESPACE_COLLAPSE as i32 as u32 {
                        len = xmlSchemaNormLen(value) as u32;
                    } else {
                        len = xmlUTF8Strlen(value) as u32;
                    }
                }
            }
            24 | 16 | 17 | 18 | 20 | 22 | 23 | 29 => {
                if !value.is_null() {
                    len = xmlSchemaNormLen(value) as u32;
                }
            }
            21 | 28 => return 0 as i32,
            _ => {
                (unsafe {
                    (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                        b"xmlschemastypes.c\0" as *const u8 as *const i8,
                        5344 as i32,
                    )
                });
            }
        }
    }
    *(borrow_mut(&mut length)).unwrap() = len as u64;
    if (unsafe { (*facet).type_0 }) as u32 == XML_SCHEMA_FACET_LENGTH as i32 as u32 {
        if len as u64 != (unsafe { (*(*facet).val).value.decimal.lo }) {
            return XML_SCHEMAV_CVC_LENGTH_VALID as i32;
        }
    } else if (unsafe { (*facet).type_0 }) as u32 == XML_SCHEMA_FACET_MINLENGTH as i32 as u32 {
        if (len as u64) < (unsafe { (*(*facet).val).value.decimal.lo }) {
            return XML_SCHEMAV_CVC_MINLENGTH_VALID as i32;
        }
    } else if len as u64 > (unsafe { (*(*facet).val).value.decimal.lo }) {
        return XML_SCHEMAV_CVC_MAXLENGTH_VALID as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlSchemaValidateLengthFacet<'a1, 'a2, 'a3, 'a4>(
    mut type_0: Option<&'a1 mut crate::src::xmlschemas::_xmlSchemaType<'a2>>,
    mut facet: *mut crate::src::xmlschemas::_xmlSchemaFacet<'a3>,
    mut value: *const u8,
    mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut length: Option<&'a4 mut u64>,
) -> i32 {
    if borrow(&type_0).is_none() {
        return -(1 as i32);
    }
    return xmlSchemaValidateLengthFacetInternal(
        facet,
        (*(borrow_mut(&mut type_0)).unwrap()).builtInType as xmlSchemaValType,
        value,
        val,
        borrow_mut(&mut length),
        XML_SCHEMA_WHITESPACE_UNKNOWN,
    );
}
#[no_mangle]
pub extern "C" fn xmlSchemaValidateLengthFacetWhtsp<'a1, 'a2>(
    mut facet: *mut crate::src::xmlschemas::_xmlSchemaFacet<'a1>,
    mut valType: u32,
    mut value: *const u8,
    mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut length: Option<&'a2 mut u64>,
    mut ws: u32,
) -> i32 {
    return xmlSchemaValidateLengthFacetInternal(
        facet,
        valType,
        value,
        val,
        borrow_mut(&mut length),
        ws,
    );
}
extern "C" fn xmlSchemaValidateFacetInternal<'a1>(
    mut facet: *mut crate::src::xmlschemas::_xmlSchemaFacet<'a1>,
    mut fws: u32,
    mut valType: u32,
    mut value: *const u8,
    mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut ws: u32,
) -> i32 {
    let mut ret: i32 = 0;
    if facet.is_null() {
        return -(1 as i32);
    }
    let mut current_block_100: u64;
    match (unsafe { (*facet).type_0 }) as u32 {
        1006 => {
            if value.is_null() {
                return -(1 as i32);
            }
            if !val.is_null()
                && !(unsafe { (*val).value.str_0 }).is_null()
                && ((unsafe { (*val).type_0 }) as u32 >= XML_SCHEMAS_STRING as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 <= XML_SCHEMAS_NORMSTRING as i32 as u32
                    || (unsafe { (*val).type_0 }) as u32 >= XML_SCHEMAS_TOKEN as i32 as u32
                        && (unsafe { (*val).type_0 }) as u32 <= XML_SCHEMAS_ENTITIES as i32 as u32
                        && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_QNAME as i32 as u32)
            {
                value = unsafe { (*val).value.str_0 };
            }
            ret = xmlRegexpExec(unsafe { (*facet).regexp }, value);
            if ret == 1 as i32 {
                return 0 as i32;
            }
            if ret == 0 as i32 {
                return XML_SCHEMAV_CVC_PATTERN_VALID as i32;
            }
            return ret;
        }
        1003 => {
            ret = xmlSchemaCompareValues(val, unsafe { (*facet).val });
            if ret == -(2 as i32) {
                return -(1 as i32);
            }
            if ret == -(1 as i32) {
                return 0 as i32;
            }
            return XML_SCHEMAV_CVC_MAXEXCLUSIVE_VALID as i32;
        }
        1002 => {
            ret = xmlSchemaCompareValues(val, unsafe { (*facet).val });
            if ret == -(2 as i32) {
                return -(1 as i32);
            }
            if ret == -(1 as i32) || ret == 0 as i32 {
                return 0 as i32;
            }
            return XML_SCHEMAV_CVC_MAXINCLUSIVE_VALID as i32;
        }
        1001 => {
            ret = xmlSchemaCompareValues(val, unsafe { (*facet).val });
            if ret == -(2 as i32) {
                return -(1 as i32);
            }
            if ret == 1 as i32 {
                return 0 as i32;
            }
            return XML_SCHEMAV_CVC_MINEXCLUSIVE_VALID as i32;
        }
        1000 => {
            ret = xmlSchemaCompareValues(val, unsafe { (*facet).val });
            if ret == -(2 as i32) {
                return -(1 as i32);
            }
            if ret == 1 as i32 || ret == 0 as i32 {
                return 0 as i32;
            }
            return XML_SCHEMAV_CVC_MININCLUSIVE_VALID as i32;
        }
        1008 => return 0 as i32,
        1007 => {
            if ws as u32 == XML_SCHEMA_WHITESPACE_UNKNOWN as i32 as u32 {
                if !(unsafe { (*facet).value }).is_null()
                    && xmlStrEqual(unsafe { (*facet).value }, value) != 0
                {
                    return 0 as i32;
                }
            } else {
                ret = xmlSchemaCompareValuesWhtspExt(
                    unsafe { (*(*facet).val).type_0 },
                    unsafe { (*facet).val },
                    unsafe { (*facet).value },
                    fws,
                    valType,
                    val,
                    value,
                    ws,
                );
                if ret == -(2 as i32) {
                    return -(1 as i32);
                }
                if ret == 0 as i32 {
                    return 0 as i32;
                }
            }
            return XML_SCHEMAV_CVC_ENUMERATION_VALID as i32;
        }
        1009 => {
            if valType as u32 == XML_SCHEMAS_QNAME as i32 as u32
                || valType as u32 == XML_SCHEMAS_NOTATION as i32 as u32
            {
                return 0 as i32;
            }
            current_block_100 = 9441801433784995173;
        }
        1010 | 1011 => {
            current_block_100 = 9441801433784995173;
        }
        1004 | 1005 => {
            if (unsafe { (*facet).val }).is_null()
                || (unsafe { (*(*facet).val).type_0 }) as u32 != XML_SCHEMAS_PINTEGER as i32 as u32
                    && (unsafe { (*(*facet).val).type_0 }) as u32
                        != XML_SCHEMAS_NNINTEGER as i32 as u32
                || (unsafe { ((*(*facet).val).value.decimal).frac() }) as i32 != 0 as i32
            {
                return -(1 as i32);
            }
            if val.is_null()
                || (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_DECIMAL as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_INTEGER as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_NPINTEGER as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_NINTEGER as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_NNINTEGER as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_PINTEGER as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_INT as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_UINT as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_LONG as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_ULONG as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_SHORT as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_USHORT as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_BYTE as i32 as u32
                    && (unsafe { (*val).type_0 }) as u32 != XML_SCHEMAS_UBYTE as i32 as u32
            {
                return -(1 as i32);
            }
            if (unsafe { (*facet).type_0 }) as u32 == XML_SCHEMA_FACET_TOTALDIGITS as i32 as u32 {
                if (unsafe { ((*val).value.decimal).total() }) as u64
                    > (unsafe { (*(*facet).val).value.decimal.lo })
                {
                    return XML_SCHEMAV_CVC_TOTALDIGITS_VALID as i32;
                }
            } else if (unsafe { (*facet).type_0 }) as u32
                == XML_SCHEMA_FACET_FRACTIONDIGITS as i32 as u32
            {
                if (unsafe { ((*val).value.decimal).frac() }) as u64
                    > (unsafe { (*(*facet).val).value.decimal.lo })
                {
                    return XML_SCHEMAV_CVC_FRACTIONDIGITS_VALID as i32;
                }
            }
            current_block_100 = 4488496028633655612;
        }
        _ => {
            (unsafe {
                (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                    b"xmlschemastypes.c\0" as *const u8 as *const i8,
                    5649 as i32,
                )
            });
            current_block_100 = 4488496028633655612;
        }
    }
    match current_block_100 {
        9441801433784995173 => {
            let mut len: u32 = 0 as i32 as u32;
            if valType as u32 == XML_SCHEMAS_QNAME as i32 as u32
                || valType as u32 == XML_SCHEMAS_NOTATION as i32 as u32
            {
                return 0 as i32;
            }
            if (unsafe { (*facet).val }).is_null()
                || (unsafe { (*(*facet).val).type_0 }) as u32 != XML_SCHEMAS_DECIMAL as i32 as u32
                    && (unsafe { (*(*facet).val).type_0 }) as u32
                        != XML_SCHEMAS_NNINTEGER as i32 as u32
                || (unsafe { ((*(*facet).val).value.decimal).frac() }) as i32 != 0 as i32
            {
                return -(1 as i32);
            }
            if !val.is_null()
                && (unsafe { (*val).type_0 }) as u32 == XML_SCHEMAS_HEXBINARY as i32 as u32
            {
                len = unsafe { (*val).value.hex.total };
            } else if !val.is_null()
                && (unsafe { (*val).type_0 }) as u32 == XML_SCHEMAS_BASE64BINARY as i32 as u32
            {
                len = unsafe { (*val).value.base64.total };
            } else {
                match valType as u32 {
                    1 | 2 => {
                        if ws as u32 == XML_SCHEMA_WHITESPACE_UNKNOWN as i32 as u32 {
                            if valType as u32 == XML_SCHEMAS_STRING as i32 as u32 {
                                len = xmlUTF8Strlen(value) as u32;
                            } else {
                                len = xmlSchemaNormLen(value) as u32;
                            }
                        } else if !value.is_null() {
                            if ws as u32 == XML_SCHEMA_WHITESPACE_COLLAPSE as i32 as u32 {
                                len = xmlSchemaNormLen(value) as u32;
                            } else {
                                len = xmlUTF8Strlen(value) as u32;
                            }
                        }
                    }
                    24 | 16 | 17 | 18 | 20 | 22 | 23 | 29 => {
                        if !value.is_null() {
                            len = xmlSchemaNormLen(value) as u32;
                        }
                    }
                    _ => {
                        (unsafe {
                            (*__xmlGenericError()).expect("non-null function pointer")(
                                *__xmlGenericErrorContext(),
                                b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                                b"xmlschemastypes.c\0" as *const u8 as *const i8,
                                5598 as i32,
                            )
                        });
                    }
                }
            }
            if (unsafe { (*facet).type_0 }) as u32 == XML_SCHEMA_FACET_LENGTH as i32 as u32 {
                if len as u64 != (unsafe { (*(*facet).val).value.decimal.lo }) {
                    return XML_SCHEMAV_CVC_LENGTH_VALID as i32;
                }
            } else if (unsafe { (*facet).type_0 }) as u32
                == XML_SCHEMA_FACET_MINLENGTH as i32 as u32
            {
                if (len as u64) < (unsafe { (*(*facet).val).value.decimal.lo }) {
                    return XML_SCHEMAV_CVC_MINLENGTH_VALID as i32;
                }
            } else if len as u64 > (unsafe { (*(*facet).val).value.decimal.lo }) {
                return XML_SCHEMAV_CVC_MAXLENGTH_VALID as i32;
            }
        }
        _ => {}
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlSchemaValidateFacet<'a1, 'a2, 'a3>(
    mut base: Option<&'a1 mut crate::src::xmlschemas::_xmlSchemaType<'a2>>,
    mut facet: *mut crate::src::xmlschemas::_xmlSchemaFacet<'a3>,
    mut value: *const u8,
    mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> i32 {
    if !val.is_null() {
        return xmlSchemaValidateFacetInternal(
            facet,
            XML_SCHEMA_WHITESPACE_UNKNOWN,
            unsafe { (*val).type_0 },
            value,
            val,
            XML_SCHEMA_WHITESPACE_UNKNOWN,
        );
    } else {
        if !borrow(&base).is_none() {
            return xmlSchemaValidateFacetInternal(
                facet,
                XML_SCHEMA_WHITESPACE_UNKNOWN,
                (*(borrow_mut(&mut base)).unwrap()).builtInType as xmlSchemaValType,
                value,
                val,
                XML_SCHEMA_WHITESPACE_UNKNOWN,
            );
        }
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlSchemaValidateFacetWhtsp<'a1>(
    mut facet: *mut crate::src::xmlschemas::_xmlSchemaFacet<'a1>,
    mut fws: u32,
    mut valType: u32,
    mut value: *const u8,
    mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut ws: u32,
) -> i32 {
    return xmlSchemaValidateFacetInternal(facet, fws, valType, value, val, ws);
}
#[no_mangle]
pub extern "C" fn xmlSchemaGetCanonValue<'a1>(
    mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut retValue: Option<&'a1 mut *const u8>,
) -> i32 {
    if borrow(&retValue).is_none() || val.is_null() {
        return -(1 as i32);
    }
    *(borrow_mut(&mut retValue)).unwrap() = 0 as *const xmlChar;
    match (unsafe { (*val).type_0 }) as u32 {
        1 => {
            if (unsafe { (*val).value.str_0 }).is_null() {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlStrdup(b"\0" as *const u8 as *const i8 as *mut xmlChar);
            } else {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlStrdup((unsafe { (*val).value.str_0 }) as *const xmlChar);
            }
        }
        2 => {
            if (unsafe { (*val).value.str_0 }).is_null() {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlStrdup(b"\0" as *const u8 as *const i8 as *mut xmlChar);
            } else {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlSchemaWhiteSpaceReplace((unsafe { (*val).value.str_0 }) as *const xmlChar);
                if (*(borrow(&retValue)).unwrap()).is_null() {
                    *(borrow_mut(&mut retValue)).unwrap() =
                        xmlStrdup((unsafe { (*val).value.str_0 }) as *const xmlChar);
                }
            }
        }
        16 | 17 | 18 | 20 | 22 | 23 | 24 | 26 | 28 | 29 => {
            if (unsafe { (*val).value.str_0 }).is_null() {
                return -(1 as i32);
            }
            *(borrow_mut(&mut retValue)).unwrap() =
                xmlSchemaCollapseString(unsafe { (*val).value.str_0 });
            if (*(borrow(&retValue)).unwrap()).is_null() {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlStrdup((unsafe { (*val).value.str_0 }) as *const xmlChar);
            }
        }
        21 => {
            if (unsafe { (*val).value.qname.uri }).is_null() {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlStrdup(unsafe { (*val).value.qname.name });
                return 0 as i32;
            } else {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlStrdup(b"{\0" as *const u8 as *const i8 as *mut xmlChar);
                *(borrow_mut(&mut retValue)).unwrap() = xmlStrcat(
                    *(borrow_mut(&mut retValue)).unwrap() as *mut xmlChar,
                    unsafe { (*val).value.qname.uri },
                );
                *(borrow_mut(&mut retValue)).unwrap() = xmlStrcat(
                    *(borrow_mut(&mut retValue)).unwrap() as *mut xmlChar,
                    b"}\0" as *const u8 as *const i8 as *mut xmlChar,
                );
                *(borrow_mut(&mut retValue)).unwrap() = xmlStrcat(
                    *(borrow_mut(&mut retValue)).unwrap() as *mut xmlChar,
                    unsafe { (*val).value.qname.uri },
                );
            }
        }
        3 => {
            if (unsafe { ((*val).value.decimal).total() }) as i32 == 1 as i32
                && (unsafe { (*val).value.decimal.lo }) == 0 as i32 as u64
            {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlStrdup(b"0.0\0" as *const u8 as *const i8 as *mut xmlChar);
            } else {
                let mut dec: crate::src::xmlschemastypes::_xmlSchemaValDecimal =
                    unsafe { (*val).value.decimal };
                let mut bufsize: i32 = 0;
                let mut buf: *mut i8 = 0 as *mut i8;
                let mut offs: *mut i8 = 0 as *mut i8;
                bufsize = dec.total() as i32 + 2 as i32;
                if dec.sign() != 0 {
                    bufsize += 1;
                }
                if dec.frac() as i32 == 0 as i32 || dec.frac() as i32 == dec.total() as i32 {
                    bufsize += 1;
                }
                buf = (unsafe { xmlMalloc.expect("non-null function pointer")(bufsize as size_t) })
                    as *mut i8;
                if buf.is_null() {
                    return -(1 as i32);
                }
                offs = buf;
                if dec.sign() != 0 {
                    let mut fresh92 = offs;
                    offs = unsafe { offs.offset(1) };
                    (unsafe { *fresh92 = '-' as i32 as i8 });
                }
                if dec.frac() as i32 == dec.total() as i32 {
                    let mut fresh93 = offs;
                    offs = unsafe { offs.offset(1) };
                    (unsafe { *fresh93 = '0' as i32 as i8 });
                    let mut fresh94 = offs;
                    offs = unsafe { offs.offset(1) };
                    (unsafe { *fresh94 = '.' as i32 as i8 });
                }
                if dec.hi != 0 as i32 as u64 {
                    (unsafe {
                        snprintf(
                            offs,
                            (bufsize as i64 - offs.offset_from(buf) as i64) as u64,
                            b"%lu%lu%lu\0" as *const u8 as *const i8,
                            dec.hi,
                            dec.mi,
                            dec.lo,
                        )
                    });
                } else if dec.mi != 0 as i32 as u64 {
                    (unsafe {
                        snprintf(
                            offs,
                            (bufsize as i64 - offs.offset_from(buf) as i64) as u64,
                            b"%lu%lu\0" as *const u8 as *const i8,
                            dec.mi,
                            dec.lo,
                        )
                    });
                } else {
                    (unsafe {
                        snprintf(
                            offs,
                            (bufsize as i64 - offs.offset_from(buf) as i64) as u64,
                            b"%lu\0" as *const u8 as *const i8,
                            dec.lo,
                        )
                    });
                }
                if dec.frac() as i32 != 0 as i32 {
                    if dec.frac() as i32 != dec.total() as i32 {
                        let mut diff: i32 = dec.total() as i32 - dec.frac() as i32;
                        (unsafe {
                            memmove(
                                offs.offset(diff as isize).offset(1 as i32 as isize)
                                    as *mut libc::c_void,
                                offs.offset(diff as isize) as *const libc::c_void,
                                (dec.frac() as i32 + 1 as i32) as u64,
                            )
                        });
                        (unsafe { *offs.offset(diff as isize) = '.' as i32 as i8 });
                    } else {
                        let mut i: u32 = 0 as i32 as u32;
                        while (unsafe { *offs.offset(i as isize) }) as i32 != 0 as i32 {
                            i = i.wrapping_add(1);
                        }
                        if i < dec.total() {
                            (unsafe {
                                memmove(
                                    offs.offset(dec.total().wrapping_sub(i) as isize)
                                        as *mut libc::c_void,
                                    offs as *const libc::c_void,
                                    i.wrapping_add(1 as i32 as u32) as u64,
                                )
                            });
                            (unsafe {
                                memset(
                                    offs as *mut libc::c_void,
                                    '0' as i32,
                                    dec.total().wrapping_sub(i) as u64,
                                )
                            });
                        }
                    }
                } else {
                    offs = unsafe { buf.offset(bufsize as isize).offset(-(1 as i32 as isize)) };
                    let mut fresh95 = offs;
                    offs = unsafe { offs.offset(-1) };
                    (unsafe { *fresh95 = 0 as i32 as i8 });
                    let mut fresh96 = offs;
                    offs = unsafe { offs.offset(-1) };
                    (unsafe { *fresh96 = '0' as i32 as i8 });
                    let mut fresh97 = offs;
                    offs = unsafe { offs.offset(-1) };
                    (unsafe { *fresh97 = '.' as i32 as i8 });
                }
                *(borrow_mut(&mut retValue)).unwrap() = buf as *mut xmlChar;
            }
        }
        30 | 34 | 31 | 32 | 33 | 37 | 41 | 39 | 35 | 36 | 38 | 40 | 42 => {
            if (unsafe { ((*val).value.decimal).total() }) as i32 == 1 as i32
                && (unsafe { (*val).value.decimal.lo }) == 0 as i32 as u64
            {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlStrdup(b"0\0" as *const u8 as *const i8 as *mut xmlChar);
            } else {
                let mut dec_0: crate::src::xmlschemastypes::_xmlSchemaValDecimal =
                    unsafe { (*val).value.decimal };
                let mut bufsize_0: i32 = dec_0.total() as i32 + 1 as i32;
                if dec_0.sign() != 0 {
                    bufsize_0 += 1;
                }
                *(borrow_mut(&mut retValue)).unwrap() =
                    (unsafe { xmlMalloc.expect("non-null function pointer")(bufsize_0 as size_t) })
                        as *const xmlChar;
                if (*(borrow_mut(&mut retValue)).unwrap()).is_null() {
                    return -(1 as i32);
                }
                if dec_0.hi != 0 as i32 as u64 {
                    if dec_0.sign() != 0 {
                        (unsafe {
                            snprintf(
                                *(borrow_mut(&mut retValue)).unwrap() as *mut i8,
                                bufsize_0 as u64,
                                b"-%lu%lu%lu\0" as *const u8 as *const i8,
                                dec_0.hi,
                                dec_0.mi,
                                dec_0.lo,
                            )
                        });
                    } else {
                        (unsafe {
                            snprintf(
                                *(borrow_mut(&mut retValue)).unwrap() as *mut i8,
                                bufsize_0 as u64,
                                b"%lu%lu%lu\0" as *const u8 as *const i8,
                                dec_0.hi,
                                dec_0.mi,
                                dec_0.lo,
                            )
                        });
                    }
                } else if dec_0.mi != 0 as i32 as u64 {
                    if dec_0.sign() != 0 {
                        (unsafe {
                            snprintf(
                                *(borrow_mut(&mut retValue)).unwrap() as *mut i8,
                                bufsize_0 as u64,
                                b"-%lu%lu\0" as *const u8 as *const i8,
                                dec_0.mi,
                                dec_0.lo,
                            )
                        });
                    } else {
                        (unsafe {
                            snprintf(
                                *(borrow_mut(&mut retValue)).unwrap() as *mut i8,
                                bufsize_0 as u64,
                                b"%lu%lu\0" as *const u8 as *const i8,
                                dec_0.mi,
                                dec_0.lo,
                            )
                        });
                    }
                } else if dec_0.sign() != 0 {
                    (unsafe {
                        snprintf(
                            *(borrow_mut(&mut retValue)).unwrap() as *mut i8,
                            bufsize_0 as u64,
                            b"-%lu\0" as *const u8 as *const i8,
                            dec_0.lo,
                        )
                    });
                } else {
                    (unsafe {
                        snprintf(
                            *(borrow_mut(&mut retValue)).unwrap() as *mut i8,
                            bufsize_0 as u64,
                            b"%lu\0" as *const u8 as *const i8,
                            dec_0.lo,
                        )
                    });
                }
            }
        }
        15 => {
            if (unsafe { (*val).value.b }) != 0 {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlStrdup(b"true\0" as *const u8 as *const i8 as *mut xmlChar);
            } else {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlStrdup(b"false\0" as *const u8 as *const i8 as *mut xmlChar);
            }
        }
        12 => {
            let mut buf_0: [i8; 100] = [0; 100];
            let mut year: u64 = 0;
            let mut mon: u64 = 0;
            let mut day: u64 = 0;
            let mut hour: u64 = 0 as i32 as u64;
            let mut min: u64 = 0 as i32 as u64;
            let mut sec: f64 = 0 as i32 as f64;
            let mut left: f64 = 0.;
            year = (unsafe { floor(labs((*val).value.dur.mon) as f64 / 12 as i32 as f64) }) as u64;
            mon = ((unsafe { labs((*val).value.dur.mon) }) as u64)
                .wrapping_sub((12 as i32 as u64).wrapping_mul(year));
            day = (unsafe { floor(fabs((*val).value.dur.sec) / 86400 as i32 as f64) }) as u64;
            left = (unsafe { fabs((*val).value.dur.sec) })
                - day.wrapping_mul(86400 as i32 as u64) as f64;
            if left > 0 as i32 as f64 {
                hour = (unsafe { floor(left / 3600 as i32 as f64) }) as u64;
                left = left - hour.wrapping_mul(3600 as i32 as u64) as f64;
                if left > 0 as i32 as f64 {
                    min = (unsafe { floor(left / 60 as i32 as f64) }) as u64;
                    sec = left - min.wrapping_mul(60 as i32 as u64) as f64;
                }
            }
            if (unsafe { (*val).value.dur.mon }) < 0 as i32 as i64
                || (unsafe { (*val).value.dur.sec }) < 0 as i32 as f64
            {
                (unsafe {
                    snprintf(
                        buf_0.as_mut_ptr(),
                        100 as i32 as u64,
                        b"P%luY%luM%luDT%luH%luM%.14gS\0" as *const u8 as *const i8,
                        year,
                        mon,
                        day,
                        hour,
                        min,
                        sec,
                    )
                });
            } else {
                (unsafe {
                    snprintf(
                        buf_0.as_mut_ptr(),
                        100 as i32 as u64,
                        b"-P%luY%luM%luDT%luH%luM%.14gS\0" as *const u8 as *const i8,
                        year,
                        mon,
                        day,
                        hour,
                        min,
                        sec,
                    )
                });
            }
            *(borrow_mut(&mut retValue)).unwrap() = xmlStrdup(buf_0.as_mut_ptr() as *mut xmlChar);
        }
        8 => {
            let mut buf_1: [i8; 30] = [0; 30];
            (unsafe {
                snprintf(
                    buf_1.as_mut_ptr(),
                    30 as i32 as u64,
                    b"%04ld\0" as *const u8 as *const i8,
                    (*val).value.date.year,
                )
            });
            *(borrow_mut(&mut retValue)).unwrap() = xmlStrdup(buf_1.as_mut_ptr() as *mut xmlChar);
        }
        6 => {
            *(borrow_mut(&mut retValue)).unwrap() =
                (unsafe { xmlMalloc.expect("non-null function pointer")(6 as i32 as size_t) })
                    as *const xmlChar;
            if (*(borrow_mut(&mut retValue)).unwrap()).is_null() {
                return -(1 as i32);
            }
            (unsafe {
                snprintf(
                    *(borrow_mut(&mut retValue)).unwrap() as *mut i8,
                    6 as i32 as u64,
                    b"--%02u\0" as *const u8 as *const i8,
                    ((*val).value.date).mon() as i32,
                )
            });
        }
        5 => {
            *(borrow_mut(&mut retValue)).unwrap() =
                (unsafe { xmlMalloc.expect("non-null function pointer")(6 as i32 as size_t) })
                    as *const xmlChar;
            if (*(borrow_mut(&mut retValue)).unwrap()).is_null() {
                return -(1 as i32);
            }
            (unsafe {
                snprintf(
                    *(borrow_mut(&mut retValue)).unwrap() as *mut i8,
                    6 as i32 as u64,
                    b"---%02u\0" as *const u8 as *const i8,
                    ((*val).value.date).day() as i32,
                )
            });
        }
        7 => {
            *(borrow_mut(&mut retValue)).unwrap() =
                (unsafe { xmlMalloc.expect("non-null function pointer")(8 as i32 as size_t) })
                    as *const xmlChar;
            if (*(borrow_mut(&mut retValue)).unwrap()).is_null() {
                return -(1 as i32);
            }
            (unsafe {
                snprintf(
                    *(borrow_mut(&mut retValue)).unwrap() as *mut i8,
                    8 as i32 as u64,
                    b"--%02u-%02u\0" as *const u8 as *const i8,
                    ((*val).value.date).mon() as i32,
                    ((*val).value.date).day() as i32,
                )
            });
        }
        9 => {
            let mut buf_2: [i8; 35] = [0; 35];
            if (unsafe { (*val).value.date.year }) < 0 as i32 as i64 {
                (unsafe {
                    snprintf(
                        buf_2.as_mut_ptr(),
                        35 as i32 as u64,
                        b"-%04ld-%02u\0" as *const u8 as *const i8,
                        labs((*val).value.date.year),
                        ((*val).value.date).mon() as i32,
                    )
                });
            } else {
                (unsafe {
                    snprintf(
                        buf_2.as_mut_ptr(),
                        35 as i32 as u64,
                        b"%04ld-%02u\0" as *const u8 as *const i8,
                        (*val).value.date.year,
                        ((*val).value.date).mon() as i32,
                    )
                });
            }
            *(borrow_mut(&mut retValue)).unwrap() = xmlStrdup(buf_2.as_mut_ptr() as *mut xmlChar);
        }
        4 => {
            let mut buf_3: [i8; 30] = [0; 30];
            if (unsafe { ((*val).value.date).tz_flag() }) != 0 {
                let mut norm: *mut crate::src::xmlschemastypes::_xmlSchemaVal =
                    0 as *mut xmlSchemaVal;
                norm = xmlSchemaDateNormalize(val, 0 as i32 as f64);
                if norm.is_null() {
                    return -(1 as i32);
                }
                (unsafe {
                    snprintf(
                        buf_3.as_mut_ptr(),
                        30 as i32 as u64,
                        b"%02u:%02u:%02.14gZ\0" as *const u8 as *const i8,
                        ((*norm).value.date).hour() as i32,
                        ((*norm).value.date).min() as i32,
                        (*norm).value.date.sec,
                    )
                });
                xmlSchemaFreeValue(norm);
            } else {
                (unsafe {
                    snprintf(
                        buf_3.as_mut_ptr(),
                        30 as i32 as u64,
                        b"%02u:%02u:%02.14g\0" as *const u8 as *const i8,
                        ((*val).value.date).hour() as i32,
                        ((*val).value.date).min() as i32,
                        (*val).value.date.sec,
                    )
                });
            }
            *(borrow_mut(&mut retValue)).unwrap() = xmlStrdup(buf_3.as_mut_ptr() as *mut xmlChar);
        }
        10 => {
            let mut buf_4: [i8; 30] = [0; 30];
            if (unsafe { ((*val).value.date).tz_flag() }) != 0 {
                let mut norm_0: *mut crate::src::xmlschemastypes::_xmlSchemaVal =
                    0 as *mut xmlSchemaVal;
                norm_0 = xmlSchemaDateNormalize(val, 0 as i32 as f64);
                if norm_0.is_null() {
                    return -(1 as i32);
                }
                (unsafe {
                    snprintf(
                        buf_4.as_mut_ptr(),
                        30 as i32 as u64,
                        b"%04ld-%02u-%02uZ\0" as *const u8 as *const i8,
                        (*norm_0).value.date.year,
                        ((*norm_0).value.date).mon() as i32,
                        ((*norm_0).value.date).day() as i32,
                    )
                });
                xmlSchemaFreeValue(norm_0);
            } else {
                (unsafe {
                    snprintf(
                        buf_4.as_mut_ptr(),
                        30 as i32 as u64,
                        b"%04ld-%02u-%02u\0" as *const u8 as *const i8,
                        (*val).value.date.year,
                        ((*val).value.date).mon() as i32,
                        ((*val).value.date).day() as i32,
                    )
                });
            }
            *(borrow_mut(&mut retValue)).unwrap() = xmlStrdup(buf_4.as_mut_ptr() as *mut xmlChar);
        }
        11 => {
            let mut buf_5: [i8; 50] = [0; 50];
            if (unsafe { ((*val).value.date).tz_flag() }) != 0 {
                let mut norm_1: *mut crate::src::xmlschemastypes::_xmlSchemaVal =
                    0 as *mut xmlSchemaVal;
                norm_1 = xmlSchemaDateNormalize(val, 0 as i32 as f64);
                if norm_1.is_null() {
                    return -(1 as i32);
                }
                (unsafe {
                    snprintf(
                        buf_5.as_mut_ptr(),
                        50 as i32 as u64,
                        b"%04ld-%02u-%02uT%02u:%02u:%02.14gZ\0" as *const u8 as *const i8,
                        (*norm_1).value.date.year,
                        ((*norm_1).value.date).mon() as i32,
                        ((*norm_1).value.date).day() as i32,
                        ((*norm_1).value.date).hour() as i32,
                        ((*norm_1).value.date).min() as i32,
                        (*norm_1).value.date.sec,
                    )
                });
                xmlSchemaFreeValue(norm_1);
            } else {
                (unsafe {
                    snprintf(
                        buf_5.as_mut_ptr(),
                        50 as i32 as u64,
                        b"%04ld-%02u-%02uT%02u:%02u:%02.14g\0" as *const u8 as *const i8,
                        (*val).value.date.year,
                        ((*val).value.date).mon() as i32,
                        ((*val).value.date).day() as i32,
                        ((*val).value.date).hour() as i32,
                        ((*val).value.date).min() as i32,
                        (*val).value.date.sec,
                    )
                });
            }
            *(borrow_mut(&mut retValue)).unwrap() = xmlStrdup(buf_5.as_mut_ptr() as *mut xmlChar);
        }
        43 => {
            *(borrow_mut(&mut retValue)).unwrap() = xmlStrdup(unsafe { (*val).value.hex.str_0 });
        }
        44 => {
            *(borrow_mut(&mut retValue)).unwrap() =
                xmlStrdup(unsafe { (*val).value.base64.str_0 });
        }
        13 => {
            let mut buf_6: [i8; 30] = [0; 30];
            (unsafe {
                snprintf(
                    buf_6.as_mut_ptr(),
                    30 as i32 as u64,
                    b"%01.14e\0" as *const u8 as *const i8,
                    (*val).value.f as f64,
                )
            });
            *(borrow_mut(&mut retValue)).unwrap() = xmlStrdup(buf_6.as_mut_ptr() as *mut xmlChar);
        }
        14 => {
            let mut buf_7: [i8; 40] = [0; 40];
            (unsafe {
                snprintf(
                    buf_7.as_mut_ptr(),
                    40 as i32 as u64,
                    b"%01.14e\0" as *const u8 as *const i8,
                    (*val).value.d,
                )
            });
            *(borrow_mut(&mut retValue)).unwrap() = xmlStrdup(buf_7.as_mut_ptr() as *mut xmlChar);
        }
        _ => {
            *(borrow_mut(&mut retValue)).unwrap() =
                xmlStrdup(b"???\0" as *const u8 as *const i8 as *mut xmlChar);
            return 1 as i32;
        }
    }
    if (*(borrow_mut(&mut retValue)).unwrap()).is_null() {
        return -(1 as i32);
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlSchemaGetCanonValueWhtsp<'a1>(
    mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
    mut retValue: Option<&'a1 mut *const u8>,
    mut ws: u32,
) -> i32 {
    if borrow(&retValue).is_none() || val.is_null() {
        return -(1 as i32);
    }
    if ws as u32 == XML_SCHEMA_WHITESPACE_UNKNOWN as i32 as u32
        || ws as u32 > XML_SCHEMA_WHITESPACE_COLLAPSE as i32 as u32
    {
        return -(1 as i32);
    }
    *(borrow_mut(&mut retValue)).unwrap() = 0 as *const xmlChar;
    match (unsafe { (*val).type_0 }) as u32 {
        1 => {
            if (unsafe { (*val).value.str_0 }).is_null() {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlStrdup(b"\0" as *const u8 as *const i8 as *mut xmlChar);
            } else if ws as u32 == XML_SCHEMA_WHITESPACE_COLLAPSE as i32 as u32 {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlSchemaCollapseString(unsafe { (*val).value.str_0 });
            } else if ws as u32 == XML_SCHEMA_WHITESPACE_REPLACE as i32 as u32 {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlSchemaWhiteSpaceReplace(unsafe { (*val).value.str_0 });
            }
            if (*(borrow_mut(&mut retValue)).unwrap()).is_null() {
                *(borrow_mut(&mut retValue)).unwrap() = xmlStrdup(unsafe { (*val).value.str_0 });
            }
        }
        2 => {
            if (unsafe { (*val).value.str_0 }).is_null() {
                *(borrow_mut(&mut retValue)).unwrap() =
                    xmlStrdup(b"\0" as *const u8 as *const i8 as *mut xmlChar);
            } else {
                if ws as u32 == XML_SCHEMA_WHITESPACE_COLLAPSE as i32 as u32 {
                    *(borrow_mut(&mut retValue)).unwrap() =
                        xmlSchemaCollapseString(unsafe { (*val).value.str_0 });
                } else {
                    *(borrow_mut(&mut retValue)).unwrap() =
                        xmlSchemaWhiteSpaceReplace(unsafe { (*val).value.str_0 });
                }
                if (*(borrow_mut(&mut retValue)).unwrap()).is_null() {
                    *(borrow_mut(&mut retValue)).unwrap() =
                        xmlStrdup(unsafe { (*val).value.str_0 });
                }
            }
        }
        _ => return xmlSchemaGetCanonValue(val, borrow_mut(&mut retValue)),
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlSchemaGetValType(
    mut val: *mut crate::src::xmlschemastypes::_xmlSchemaVal,
) -> u32 {
    if val.is_null() {
        return XML_SCHEMAS_UNKNOWN;
    }
    return unsafe { (*val).type_0 };
}
use crate::laertes_rt::*;
