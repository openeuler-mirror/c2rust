use ::libc;
extern "C" {
    
    
    
    
    static mut stdout: * mut crate::src::HTMLtree::_IO_FILE;
    fn xmlStrlen(str: * const u8) -> i32;
    fn xmlStrchr(str: * const u8, val: u8) -> * const u8;
    fn fwrite(
        _: * const core::ffi::c_void,
        _: u64,
        _: u64,
        _: * mut crate::src::HTMLtree::_IO_FILE,
    ) -> u64;
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn memmove(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn xmlBufferFree(buf: * mut crate::src::HTMLtree::_xmlBuffer);
    
    
    
    
    
    
    
}
pub use crate::src::error::__xmlSimpleError;
pub use crate::src::globals::__xmlBufferAllocScheme;
pub use crate::src::globals::__xmlDefaultBufferSize;
pub use crate::src::HTMLtree::_IO_marker;
pub use crate::src::catalog::_IO_wide_data;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub use crate::src::globals::xmlMallocAtomic;
pub use crate::src::globals::xmlRealloc;
pub use crate::src::relaxng::_IO_codecvt;
pub use crate::src::dict::_xmlDict;
pub type xmlChar = u8;
pub type size_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::HTMLtree::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::HTMLtree::_IO_FILE;
// #[derive(Copy, Clone)]

pub type _xmlParserInputBuffer = crate::src::HTMLparser::_xmlParserInputBuffer;
pub type xmlBufPtr = * mut crate::src::buf::_xmlBuf;
pub type xmlBuf = crate::src::buf::_xmlBuf;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlBuf {
    pub content: * mut u8,
    pub compat_use: u32,
    pub compat_size: u32,
    pub alloc: u32,
    pub contentIO: * mut u8,
    pub use_0: u64,
    pub size: u64,
    pub buffer: * mut crate::src::HTMLtree::_xmlBuffer,
    pub error: i32,
}
impl _xmlBuf {
    pub const fn new() -> Self {
        _xmlBuf {
        content: (0 as * mut u8),
        compat_use: 0,
        compat_size: 0,
        alloc: 0,
        contentIO: (0 as * mut u8),
        use_0: 0,
        size: 0,
        buffer: (0 as * mut crate::src::HTMLtree::_xmlBuffer),
        error: 0
        }
    }
}

impl std::default::Default for _xmlBuf {
    fn default() -> Self { _xmlBuf::new() }
}

pub type xmlBufferPtr = * mut crate::src::HTMLtree::_xmlBuffer;
pub type xmlBuffer = crate::src::HTMLtree::_xmlBuffer;
// #[derive(Copy, Clone)]

pub type _xmlBuffer = crate::src::HTMLtree::_xmlBuffer;
pub type xmlBufferAllocationScheme = u32;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
pub type xmlCharEncodingHandlerPtr = * mut crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub type _xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type iconv_t = * mut core::ffi::c_void;
pub type xmlCharEncodingOutputFunc = Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>;
pub type xmlCharEncodingInputFunc = Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>;
pub type xmlInputCloseCallback = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type xmlInputReadCallback = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut i8,_: i32,) -> i32>;
pub type xmlParserInputBuffer = crate::src::HTMLparser::_xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = * mut crate::src::HTMLparser::_xmlParserInputBuffer;
// #[derive(Copy, Clone)]

pub type _xmlParserInput = crate::src::HTMLparser::_xmlParserInput;
pub type xmlParserInputDeallocate = Option<unsafe extern "C"  fn(_: * mut u8,) -> ()>;
pub type xmlParserInput = crate::src::HTMLparser::_xmlParserInput;
pub type xmlParserInputPtr = * mut crate::src::HTMLparser::_xmlParserInput;
// #[derive(Copy, Clone)]

pub type _xmlNode = crate::src::HTMLparser::_xmlNode;
pub type xmlNs = crate::src::HTMLparser::_xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlNs = crate::src::HTMLparser::_xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlDoc = crate::src::HTMLparser::_xmlDoc;
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

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
pub type xmlNodePtr = * mut crate::src::HTMLparser::_xmlNode;
pub type xmlNode = crate::src::HTMLparser::_xmlNode;
pub type xmlFreeFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>;
pub type xmlReallocFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: u64,) -> * mut core::ffi::c_void>;
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
unsafe extern "C" fn xmlBufMemoryError(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut extra: * const i8,
) {
    __xmlSimpleError(
        XML_FROM_BUFFER as i32,
        XML_ERR_NO_MEMORY as i32,
        0 as xmlNodePtr,
        0 as *const i8,
        extra,
    );
    if !buf.is_null() && (*buf).error == 0 as i32 {
        (*buf).error = XML_ERR_NO_MEMORY as i32;
    }
}
unsafe extern "C" fn xmlBufOverflowError(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut extra: * const i8,
) {
    __xmlSimpleError(
        XML_FROM_BUFFER as i32,
        XML_BUF_OVERFLOW as i32,
        0 as xmlNodePtr,
        0 as *const i8,
        extra,
    );
    if !buf.is_null() && (*buf).error == 0 as i32 {
        (*buf).error = XML_BUF_OVERFLOW as i32;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufCreate() -> * mut crate::src::buf::_xmlBuf {
    let mut ret: * mut crate::src::buf::_xmlBuf = 0 as *mut xmlBuf;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlBuf>() as u64) as xmlBufPtr;
    if ret.is_null() {
        xmlBufMemoryError(
            0 as xmlBufPtr,
            b"creating buffer\0" as *const u8 as *const i8,
        );
        return 0 as xmlBufPtr;
    }
    (*ret).use_0 = 0 as i32 as size_t;
    (*ret).error = 0 as i32;
    let fresh0 = &mut ((*ret).buffer);
    *fresh0 = 0 as xmlBufferPtr;
    (*ret).size = *(__xmlDefaultBufferSize()).unwrap() as size_t;
    if (*ret).size < 2147483647 as i32 as u64 {
        (*ret).compat_size = (*ret).size as u32;
    } else {
        (*ret).compat_size = 2147483647 as i32 as u32;
    }
    if (*ret).use_0 < 2147483647 as i32 as u64 {
        (*ret).compat_use = (*ret).use_0 as u32;
    } else {
        (*ret).compat_use = 2147483647 as i32 as u32;
    }
    (*ret).alloc = *(__xmlBufferAllocScheme()).unwrap();
    let fresh1 = &mut ((*ret).content);
    *fresh1 = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(((*ret).size).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64))
        as *mut xmlChar;
    if ((*ret).content).is_null() {
        xmlBufMemoryError(ret, b"creating buffer\0" as *const u8 as *const i8);
        xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
        return 0 as xmlBufPtr;
    }
    *((*ret).content).offset(0 as i32 as isize) = 0 as i32 as xmlChar;
    let fresh2 = &mut ((*ret).contentIO);
    *fresh2 = 0 as *mut xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufCreateSize(mut size: u64) -> * mut crate::src::buf::_xmlBuf {
    let mut ret: * mut crate::src::buf::_xmlBuf = 0 as *mut xmlBuf;
    if size == -(1 as i32) as size_t {
        return 0 as xmlBufPtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlBuf>() as u64) as xmlBufPtr;
    if ret.is_null() {
        xmlBufMemoryError(
            0 as xmlBufPtr,
            b"creating buffer\0" as *const u8 as *const i8,
        );
        return 0 as xmlBufPtr;
    }
    (*ret).use_0 = 0 as i32 as size_t;
    (*ret).error = 0 as i32;
    let fresh3 = &mut ((*ret).buffer);
    *fresh3 = 0 as xmlBufferPtr;
    (*ret).alloc = *(__xmlBufferAllocScheme()).unwrap();
    (*ret)
        .size = if size != 0 {
        size.wrapping_add(1 as i32 as u64)
    } else {
        0 as i32 as u64
    };
    if (*ret).size < 2147483647 as i32 as u64 {
        (*ret).compat_size = (*ret).size as u32;
    } else {
        (*ret).compat_size = 2147483647 as i32 as u32;
    }
    if (*ret).use_0 < 2147483647 as i32 as u64 {
        (*ret).compat_use = (*ret).use_0 as u32;
    } else {
        (*ret).compat_use = 2147483647 as i32 as u32;
    }
    if (*ret).size != 0 {
        let fresh4 = &mut ((*ret).content);
        *fresh4 = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )(
            ((*ret).size).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        ) as *mut xmlChar;
        if ((*ret).content).is_null() {
            xmlBufMemoryError(
                ret,
                b"creating buffer\0" as *const u8 as *const i8,
            );
            xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
            return 0 as xmlBufPtr;
        }
        *((*ret).content)
            .offset(0 as i32 as isize) = 0 as i32 as xmlChar;
    } else {
        let fresh5 = &mut ((*ret).content);
        *fresh5 = 0 as *mut xmlChar;
    }
    let fresh6 = &mut ((*ret).contentIO);
    *fresh6 = 0 as *mut xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufDetach<'a1>(mut buf: Option<&'a1 mut crate::src::buf::_xmlBuf>) -> * mut u8 {
    let mut ret: * mut u8 = 0 as *mut xmlChar;
    if borrow(& buf).is_none() {
        return 0 as *mut xmlChar;
    }
    if (*(borrow(& buf)).unwrap()).alloc as u32
        == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
    {
        return 0 as *mut xmlChar;
    }
    if !((*(borrow_mut(&mut buf)).unwrap()).buffer).is_null() {
        return 0 as *mut xmlChar;
    }
    if (*(borrow(& buf)).unwrap()).error != 0 {
        return 0 as *mut xmlChar;
    }
    ret = (*(borrow_mut(&mut buf)).unwrap()).content;
    let fresh7 = &mut ((*(borrow_mut(&mut buf)).unwrap()).content);
    *fresh7 = 0 as *mut xmlChar;
    (*(borrow_mut(&mut buf)).unwrap()).size = 0 as i32 as size_t;
    (*(borrow_mut(&mut buf)).unwrap()).use_0 = 0 as i32 as size_t;
    if (*(borrow(& buf)).unwrap()).size < 2147483647 as i32 as u64 {
        (*(borrow_mut(&mut buf)).unwrap()).compat_size = (*(borrow_mut(&mut buf)).unwrap()).size as u32;
    } else {
        (*(borrow_mut(&mut buf)).unwrap()).compat_size = 2147483647 as i32 as u32;
    }
    if (*(borrow(& buf)).unwrap()).use_0 < 2147483647 as i32 as u64 {
        (*(borrow_mut(&mut buf)).unwrap()).compat_use = (*(borrow_mut(&mut buf)).unwrap()).use_0 as u32;
    } else {
        (*(borrow_mut(&mut buf)).unwrap()).compat_use = 2147483647 as i32 as u32;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufCreateStatic(
    mut mem: * mut core::ffi::c_void,
    mut size: u64,
) -> * mut crate::src::buf::_xmlBuf {
    let mut ret: * mut crate::src::buf::_xmlBuf = (0 as * mut crate::src::buf::_xmlBuf);
    if mem.is_null() {
        return (0 as * mut crate::src::buf::_xmlBuf);
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlBuf>() as u64) as xmlBufPtr;
    if ret.is_null() {
        xmlBufMemoryError(
            0 as xmlBufPtr,
            b"creating buffer\0" as *const u8 as *const i8,
        );
        return (0 as * mut crate::src::buf::_xmlBuf);
    }
    (*ret).use_0 = size;
    (*ret).size = size;
    if (*ret).size < 2147483647 as i32 as u64 {
        (*ret).compat_size = (*ret).size as u32;
    } else {
        (*ret).compat_size = 2147483647 as i32 as u32;
    }
    if (*ret).use_0 < 2147483647 as i32 as u64 {
        (*ret).compat_use = (*ret).use_0 as u32;
    } else {
        (*ret).compat_use = 2147483647 as i32 as u32;
    }
    (*ret).alloc = XML_BUFFER_ALLOC_IMMUTABLE;
    let fresh8 = &mut ((*ret).content);
    *fresh8 = mem as *mut xmlChar;
    (*ret).error = 0 as i32;
    let fresh9 = &mut ((*ret).buffer);
    *fresh9 = 0 as xmlBufferPtr;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufGetAllocationScheme(mut buf: * mut crate::src::buf::_xmlBuf) -> i32 {
    if buf.is_null() {
        return -(1 as i32);
    }
    return (*buf).alloc as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufSetAllocationScheme(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut scheme: u32,
) -> i32 {
    if buf.is_null() || (*buf).error != 0 as i32 {
        return -(1 as i32);
    }
    if (*buf).alloc as u32
        == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
        || (*buf).alloc as u32
            == XML_BUFFER_ALLOC_IO as i32 as u32
    {
        return -(1 as i32);
    }
    if scheme as u32 == XML_BUFFER_ALLOC_DOUBLEIT as i32 as u32
        || scheme as u32
            == XML_BUFFER_ALLOC_EXACT as i32 as u32
        || scheme as u32
            == XML_BUFFER_ALLOC_HYBRID as i32 as u32
        || scheme as u32
            == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
        || scheme as u32
            == XML_BUFFER_ALLOC_BOUNDED as i32 as u32
    {
        (*buf).alloc = scheme;
        if !((*buf).buffer).is_null() {
            (*(*buf).buffer).alloc = scheme;
        }
        return 0 as i32;
    }
    if scheme as u32 == XML_BUFFER_ALLOC_IO as i32 as u32 {
        (*buf).alloc = XML_BUFFER_ALLOC_IO;
        let fresh10 = &mut ((*buf).contentIO);
        *fresh10 = (*buf).content;
    }
    return -(1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufFree(mut buf: * mut crate::src::buf::_xmlBuf) {
    if buf.is_null() {
        return;
    }
    if (*buf).alloc as u32 == XML_BUFFER_ALLOC_IO as i32 as u32
        && !((*buf).contentIO).is_null()
    {
        xmlFree
            .expect("non-null function pointer")((*buf).contentIO as *mut libc::c_void);
    } else if !((*buf).content).is_null()
            && (*buf).alloc as u32
                != XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
        {
        xmlFree.expect("non-null function pointer")((*buf).content as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufEmpty(mut buf: * mut crate::src::buf::_xmlBuf) {
    if buf.is_null() || (*buf).error != 0 as i32 {
        return;
    }
    if ((*buf).content).is_null() {
        return;
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    (*buf).use_0 = 0 as i32 as size_t;
    if (*buf).alloc as u32
        == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
    {
        let fresh11 = &mut ((*buf).content);
        *fresh11 = b"\0" as *const u8 as *const i8 as *mut xmlChar;
    } else if (*buf).alloc as u32
            == XML_BUFFER_ALLOC_IO as i32 as u32
            && !((*buf).contentIO).is_null()
        {
        let mut start_buf: u64 = ((*buf).content).offset_from((*buf).contentIO)
            as i64 as size_t;
        let fresh12 = &mut ((*buf).size);
        *fresh12 = (*fresh12 as u64).wrapping_add(start_buf) as size_t
            as size_t;
        let fresh13 = &mut ((*buf).content);
        *fresh13 = (*buf).contentIO;
        *((*buf).content)
            .offset(0 as i32 as isize) = 0 as i32 as xmlChar;
    } else {
        *((*buf).content)
            .offset(0 as i32 as isize) = 0 as i32 as xmlChar;
    }
    if (*buf).size < 2147483647 as i32 as u64 {
        (*buf).compat_size = (*buf).size as u32;
    } else {
        (*buf).compat_size = 2147483647 as i32 as u32;
    }
    if (*buf).use_0 < 2147483647 as i32 as u64 {
        (*buf).compat_use = (*buf).use_0 as u32;
    } else {
        (*buf).compat_use = 2147483647 as i32 as u32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufShrink(mut buf: * mut crate::src::buf::_xmlBuf, mut len: u64) -> u64 {
    if buf.is_null() || (*buf).error != 0 as i32 {
        return 0 as i32 as size_t;
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    if len == 0 as i32 as u64 {
        return 0 as i32 as size_t;
    }
    if len > (*buf).use_0 {
        return 0 as i32 as size_t;
    }
    let fresh14 = &mut ((*buf).use_0);
    *fresh14 = (*fresh14 as u64).wrapping_sub(len) as size_t as size_t;
    if (*buf).alloc as u32
        == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
        || (*buf).alloc as u32
            == XML_BUFFER_ALLOC_IO as i32 as u32
            && !((*buf).contentIO).is_null()
    {
        let fresh15 = &mut ((*buf).content);
        *fresh15 = (*fresh15).offset(len as isize);
        let fresh16 = &mut ((*buf).size);
        *fresh16 = (*fresh16 as u64).wrapping_sub(len) as size_t as size_t;
        if (*buf).alloc as u32
            == XML_BUFFER_ALLOC_IO as i32 as u32
            && !((*buf).contentIO).is_null()
        {
            let mut start_buf: u64 = ((*buf).content).offset_from((*buf).contentIO)
                as i64 as size_t;
            if start_buf >= (*buf).size {
                memmove(
                    (*buf).contentIO as *mut libc::c_void,
                    &mut *((*buf).content).offset(0 as i32 as isize)
                        as *mut xmlChar as *const libc::c_void,
                    (*buf).use_0,
                );
                let fresh17 = &mut ((*buf).content);
                *fresh17 = (*buf).contentIO;
                *((*buf).content)
                    .offset((*buf).use_0 as isize) = 0 as i32 as xmlChar;
                let fresh18 = &mut ((*buf).size);
                *fresh18 = (*fresh18 as u64).wrapping_add(start_buf) as size_t
                    as size_t;
            }
        }
    } else {
        memmove(
            (*buf).content as *mut libc::c_void,
            &mut *((*buf).content).offset(len as isize) as *mut xmlChar
                as *const libc::c_void,
            (*buf).use_0,
        );
        *((*buf).content).offset((*buf).use_0 as isize) = 0 as i32 as xmlChar;
    }
    if (*buf).size < 2147483647 as i32 as u64 {
        (*buf).compat_size = (*buf).size as u32;
    } else {
        (*buf).compat_size = 2147483647 as i32 as u32;
    }
    if (*buf).use_0 < 2147483647 as i32 as u64 {
        (*buf).compat_use = (*buf).use_0 as u32;
    } else {
        (*buf).compat_use = 2147483647 as i32 as u32;
    }
    return len;
}
unsafe extern "C" fn xmlBufGrowInternal(mut buf: * mut crate::src::buf::_xmlBuf, mut len: u64) -> u64 {
    let mut size: u64 = 0;
    let mut newbuf: * mut u8 = 0 as *mut xmlChar;
    if buf.is_null() || (*buf).error != 0 as i32 {
        return 0 as i32 as size_t;
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    if (*buf).alloc as u32
        == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
    {
        return 0 as i32 as size_t;
    }
    if len < ((*buf).size).wrapping_sub((*buf).use_0) {
        return ((*buf).size)
            .wrapping_sub((*buf).use_0)
            .wrapping_sub(1 as i32 as u64);
    }
    if len >= (-(1 as i32) as size_t).wrapping_sub((*buf).use_0) {
        xmlBufMemoryError(
            buf,
            b"growing buffer past SIZE_MAX\0" as *const u8 as *const i8,
        );
        return 0 as i32 as size_t;
    }
    if (*buf).size > len {
        size = if (*buf).size
            > (-(1 as i32) as size_t)
                .wrapping_div(2 as i32 as u64)
        {
            -(1 as i32) as size_t
        } else {
            ((*buf).size).wrapping_mul(2 as i32 as u64)
        };
    } else {
        size = ((*buf).use_0).wrapping_add(len);
        size = if size
            > (-(1 as i32) as size_t)
                .wrapping_sub(100 as i32 as u64)
        {
            -(1 as i32) as size_t
        } else {
            size.wrapping_add(100 as i32 as u64)
        };
    }
    if (*buf).alloc as u32
        == XML_BUFFER_ALLOC_BOUNDED as i32 as u32
    {
        if ((*buf).use_0)
            .wrapping_add(len)
            .wrapping_add(1 as i32 as u64)
            >= 10000000 as i32 as u64
            || (*buf).size >= 10000000 as i32 as u64
        {
            xmlBufMemoryError(
                buf,
                b"buffer error: text too long\n\0" as *const u8 as *const i8,
            );
            return 0 as i32 as size_t;
        }
        if size >= 10000000 as i32 as u64 {
            size = 10000000 as i32 as size_t;
        }
    }
    if (*buf).alloc as u32 == XML_BUFFER_ALLOC_IO as i32 as u32
        && !((*buf).contentIO).is_null()
    {
        let mut start_buf: u64 = ((*buf).content).offset_from((*buf).contentIO)
            as i64 as size_t;
        newbuf = xmlRealloc
            .expect(
                "non-null function pointer",
            )((*buf).contentIO as *mut libc::c_void, start_buf.wrapping_add(size))
            as *mut xmlChar;
        if newbuf.is_null() {
            xmlBufMemoryError(
                buf,
                b"growing buffer\0" as *const u8 as *const i8,
            );
            return 0 as i32 as size_t;
        }
        let fresh19 = &mut ((*buf).contentIO);
        *fresh19 = newbuf;
        let fresh20 = &mut ((*buf).content);
        *fresh20 = newbuf.offset(start_buf as isize);
    } else {
        newbuf = xmlRealloc
            .expect(
                "non-null function pointer",
            )((*buf).content as *mut libc::c_void, size) as *mut xmlChar;
        if newbuf.is_null() {
            xmlBufMemoryError(
                buf,
                b"growing buffer\0" as *const u8 as *const i8,
            );
            return 0 as i32 as size_t;
        }
        let fresh21 = &mut ((*buf).content);
        *fresh21 = newbuf;
    }
    (*buf).size = size;
    if (*buf).size < 2147483647 as i32 as u64 {
        (*buf).compat_size = (*buf).size as u32;
    } else {
        (*buf).compat_size = 2147483647 as i32 as u32;
    }
    if (*buf).use_0 < 2147483647 as i32 as u64 {
        (*buf).compat_use = (*buf).use_0 as u32;
    } else {
        (*buf).compat_use = 2147483647 as i32 as u32;
    }
    return ((*buf).size)
        .wrapping_sub((*buf).use_0)
        .wrapping_sub(1 as i32 as u64);
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufGrow(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut len: i32,
) -> i32 {
    let mut ret: u64 = 0;
    if buf.is_null() || len < 0 as i32 {
        return -(1 as i32);
    }
    if len == 0 as i32 {
        return 0 as i32;
    }
    ret = xmlBufGrowInternal(buf, len as size_t);
    if (*buf).error != 0 as i32 {
        return -(1 as i32);
    }
    return ret as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufDump<'a1>(mut file: * mut crate::src::HTMLtree::_IO_FILE, mut buf: Option<&'a1 mut crate::src::buf::_xmlBuf>) -> u64 {
    let mut ret: u64 = 0;
    if borrow(& buf).is_none() || (*(borrow(& buf)).unwrap()).error != 0 as i32 {
        return 0 as i32 as size_t;
    }
    if ((*(borrow_mut(&mut buf)).unwrap()).content).is_null() {
        return 0 as i32 as size_t;
    }
    if (*(borrow(& buf)).unwrap()).size != (*(borrow(& buf)).unwrap()).compat_size as size_t {
        if (*(borrow(& buf)).unwrap()).compat_size < 2147483647 as i32 as u32 {
            (*(borrow_mut(&mut buf)).unwrap()).size = (*(borrow_mut(&mut buf)).unwrap()).compat_size as size_t;
        }
    }
    if (*(borrow(& buf)).unwrap()).use_0 != (*(borrow(& buf)).unwrap()).compat_use as size_t {
        if (*(borrow(& buf)).unwrap()).compat_use < 2147483647 as i32 as u32 {
            (*(borrow_mut(&mut buf)).unwrap()).use_0 = (*(borrow_mut(&mut buf)).unwrap()).compat_use as size_t;
        }
    }
    if file.is_null() {
        file = stdout;
    }
    ret = fwrite(
        (*(borrow(& buf)).unwrap()).content as *const libc::c_void,
        ::std::mem::size_of::<xmlChar>() as u64,
        (*(borrow_mut(&mut buf)).unwrap()).use_0,
        file,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufContent(mut buf: * const crate::src::buf::_xmlBuf) -> * mut u8 {
    if buf.is_null() || (*buf).error != 0 {
        return 0 as *mut xmlChar;
    }
    return (*buf).content;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufEnd(mut buf: * mut crate::src::buf::_xmlBuf) -> * mut u8 {
    if buf.is_null() || (*buf).error != 0 {
        return 0 as *mut xmlChar;
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    return &mut *((*buf).content).offset((*buf).use_0 as isize) as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufAddLen(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut len: u64,
) -> i32 {
    if buf.is_null() || (*buf).error != 0 {
        return -(1 as i32);
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    if len >= ((*buf).size).wrapping_sub((*buf).use_0) {
        return -(1 as i32);
    }
    let fresh22 = &mut ((*buf).use_0);
    *fresh22 = (*fresh22 as u64).wrapping_add(len) as size_t as size_t;
    *((*buf).content).offset((*buf).use_0 as isize) = 0 as i32 as xmlChar;
    if (*buf).size < 2147483647 as i32 as u64 {
        (*buf).compat_size = (*buf).size as u32;
    } else {
        (*buf).compat_size = 2147483647 as i32 as u32;
    }
    if (*buf).use_0 < 2147483647 as i32 as u64 {
        (*buf).compat_use = (*buf).use_0 as u32;
    } else {
        (*buf).compat_use = 2147483647 as i32 as u32;
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufLength(buf: * mut crate::src::buf::_xmlBuf) -> u64 {
    if buf.is_null() || (*buf).error != 0 {
        return 0 as i32 as size_t;
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    return (*buf).use_0;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufUse(buf: * mut crate::src::buf::_xmlBuf) -> u64 {
    if buf.is_null() || (*buf).error != 0 {
        return 0 as i32 as size_t;
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    return (*buf).use_0;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufAvail(buf: * mut crate::src::buf::_xmlBuf) -> u64 {
    if buf.is_null() || (*buf).error != 0 {
        return 0 as i32 as size_t;
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    return if (*buf).size > (*buf).use_0 {
        ((*buf).size)
            .wrapping_sub((*buf).use_0)
            .wrapping_sub(1 as i32 as u64)
    } else {
        0 as i32 as u64
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufIsEmpty(buf: * mut crate::src::buf::_xmlBuf) -> i32 {
    if buf.is_null() || (*buf).error != 0 {
        return -(1 as i32);
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    return ((*buf).use_0 == 0 as i32 as u64) as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufResize(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut size: u64,
) -> i32 {
    let mut newSize: u64 = 0;
    let mut rebuf: * mut u8 = 0 as *mut xmlChar;
    let mut start_buf: u64 = 0;
    if buf.is_null() || (*buf).error != 0 {
        return 0 as i32;
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    if (*buf).alloc as u32
        == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
    {
        return 0 as i32;
    }
    if (*buf).alloc as u32
        == XML_BUFFER_ALLOC_BOUNDED as i32 as u32
    {
        if size >= 10000000 as i32 as u64 {
            xmlBufMemoryError(
                buf,
                b"buffer error: text too long\n\0" as *const u8 as *const i8,
            );
            return 0 as i32;
        }
    }
    if size < (*buf).size {
        return 1 as i32;
    }
    match (*buf).alloc as u32 {
        3 | 0 => {
            if (*buf).size == 0 as i32 as u64 {
                newSize = if size
                    > (-(1 as i32) as size_t)
                        .wrapping_sub(10 as i32 as u64)
                {
                    -(1 as i32) as size_t
                } else {
                    size.wrapping_add(10 as i32 as u64)
                };
            } else {
                newSize = (*buf).size;
            }
            while size > newSize {
                if newSize
                    > (-(1 as i32) as size_t)
                        .wrapping_div(2 as i32 as u64)
                {
                    xmlBufMemoryError(
                        buf,
                        b"growing buffer\0" as *const u8 as *const i8,
                    );
                    return 0 as i32;
                }
                newSize = (newSize as u64)
                    .wrapping_mul(2 as i32 as u64) as size_t as size_t;
            }
        }
        1 => {
            newSize = if size
                > (-(1 as i32) as size_t)
                    .wrapping_sub(10 as i32 as u64)
            {
                -(1 as i32) as size_t
            } else {
                size.wrapping_add(10 as i32 as u64)
            };
        }
        4 => {
            if (*buf).use_0 < 4096 as i32 as u64 {
                newSize = size;
            } else {
                newSize = (*buf).size;
                while size > newSize {
                    if newSize
                        > (-(1 as i32) as size_t)
                            .wrapping_div(2 as i32 as u64)
                    {
                        xmlBufMemoryError(
                            buf,
                            b"growing buffer\0" as *const u8 as *const i8,
                        );
                        return 0 as i32;
                    }
                    newSize = (newSize as u64)
                        .wrapping_mul(2 as i32 as u64) as size_t
                        as size_t;
                }
            }
        }
        _ => {
            newSize = if size
                > (-(1 as i32) as size_t)
                    .wrapping_sub(10 as i32 as u64)
            {
                -(1 as i32) as size_t
            } else {
                size.wrapping_add(10 as i32 as u64)
            };
        }
    }
    if (*buf).alloc as u32 == XML_BUFFER_ALLOC_IO as i32 as u32
        && !((*buf).contentIO).is_null()
    {
        start_buf = ((*buf).content).offset_from((*buf).contentIO) as i64
            as size_t;
        if start_buf > newSize {
            memmove(
                (*buf).contentIO as *mut libc::c_void,
                (*buf).content as *const libc::c_void,
                (*buf).use_0,
            );
            let fresh23 = &mut ((*buf).content);
            *fresh23 = (*buf).contentIO;
            *((*buf).content)
                .offset((*buf).use_0 as isize) = 0 as i32 as xmlChar;
            let fresh24 = &mut ((*buf).size);
            *fresh24 = (*fresh24 as u64).wrapping_add(start_buf) as size_t
                as size_t;
        } else {
            rebuf = xmlRealloc
                .expect(
                    "non-null function pointer",
                )((*buf).contentIO as *mut libc::c_void, start_buf.wrapping_add(newSize))
                as *mut xmlChar;
            if rebuf.is_null() {
                xmlBufMemoryError(
                    buf,
                    b"growing buffer\0" as *const u8 as *const i8,
                );
                return 0 as i32;
            }
            let fresh25 = &mut ((*buf).contentIO);
            *fresh25 = rebuf;
            let fresh26 = &mut ((*buf).content);
            *fresh26 = rebuf.offset(start_buf as isize);
        }
    } else {
        if ((*buf).content).is_null() {
            rebuf = xmlMallocAtomic.expect("non-null function pointer")(newSize)
                as *mut xmlChar;
            (*buf).use_0 = 0 as i32 as size_t;
            *rebuf.offset((*buf).use_0 as isize) = 0 as i32 as xmlChar;
        } else if ((*buf).size).wrapping_sub((*buf).use_0)
                < 100 as i32 as u64
            {
            rebuf = xmlRealloc
                .expect(
                    "non-null function pointer",
                )((*buf).content as *mut libc::c_void, newSize) as *mut xmlChar;
        } else {
            rebuf = xmlMallocAtomic.expect("non-null function pointer")(newSize)
                as *mut xmlChar;
            if !rebuf.is_null() {
                memcpy(
                    rebuf as *mut libc::c_void,
                    (*buf).content as *const libc::c_void,
                    (*buf).use_0,
                );
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*buf).content as *mut libc::c_void);
                *rebuf.offset((*buf).use_0 as isize) = 0 as i32 as xmlChar;
            }
        }
        if rebuf.is_null() {
            xmlBufMemoryError(
                buf,
                b"growing buffer\0" as *const u8 as *const i8,
            );
            return 0 as i32;
        }
        let fresh27 = &mut ((*buf).content);
        *fresh27 = rebuf;
    }
    (*buf).size = newSize;
    if (*buf).size < 2147483647 as i32 as u64 {
        (*buf).compat_size = (*buf).size as u32;
    } else {
        (*buf).compat_size = 2147483647 as i32 as u32;
    }
    if (*buf).use_0 < 2147483647 as i32 as u64 {
        (*buf).compat_use = (*buf).use_0 as u32;
    } else {
        (*buf).compat_use = 2147483647 as i32 as u32;
    }
    return 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufAdd(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut str: * const u8,
    mut len: i32,
) -> i32 {
    let mut needSize: u64 = 0;
    if str.is_null() || buf.is_null() || (*buf).error != 0 {
        return -(1 as i32);
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    if (*buf).alloc as u32
        == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
    {
        return -(1 as i32);
    }
    if len < -(1 as i32) {
        return -(1 as i32);
    }
    if len == 0 as i32 {
        return 0 as i32;
    }
    if len < 0 as i32 {
        len = xmlStrlen(str);
    }
    if len < 0 as i32 {
        return -(1 as i32);
    }
    if len == 0 as i32 {
        return 0 as i32;
    }
    if len as size_t >= ((*buf).size).wrapping_sub((*buf).use_0) {
        if len as size_t >= (-(1 as i32) as size_t).wrapping_sub((*buf).use_0) {
            xmlBufMemoryError(
                buf,
                b"growing buffer past SIZE_MAX\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        needSize = ((*buf).use_0)
            .wrapping_add(len as u64)
            .wrapping_add(1 as i32 as u64);
        if (*buf).alloc as u32
            == XML_BUFFER_ALLOC_BOUNDED as i32 as u32
        {
            if needSize >= 10000000 as i32 as u64 {
                xmlBufMemoryError(
                    buf,
                    b"buffer error: text too long\n\0" as *const u8
                        as *const i8,
                );
                return -(1 as i32);
            }
        }
        if xmlBufResize(buf, needSize) == 0 {
            xmlBufMemoryError(
                buf,
                b"growing buffer\0" as *const u8 as *const i8,
            );
            return XML_ERR_NO_MEMORY as i32;
        }
    }
    memmove(
        &mut *((*buf).content).offset((*buf).use_0 as isize) as *mut xmlChar
            as *mut libc::c_void,
        str as *const libc::c_void,
        (len as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    );
    let fresh28 = &mut ((*buf).use_0);
    *fresh28 = (*fresh28 as u64).wrapping_add(len as u64) as size_t
        as size_t;
    *((*buf).content).offset((*buf).use_0 as isize) = 0 as i32 as xmlChar;
    if (*buf).size < 2147483647 as i32 as u64 {
        (*buf).compat_size = (*buf).size as u32;
    } else {
        (*buf).compat_size = 2147483647 as i32 as u32;
    }
    if (*buf).use_0 < 2147483647 as i32 as u64 {
        (*buf).compat_use = (*buf).use_0 as u32;
    } else {
        (*buf).compat_use = 2147483647 as i32 as u32;
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufCat(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut str: * const u8,
) -> i32 {
    if buf.is_null() || (*buf).error != 0 {
        return -(1 as i32);
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    if (*buf).alloc as u32
        == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
    {
        return -(1 as i32);
    }
    if str.is_null() {
        return -(1 as i32);
    }
    return xmlBufAdd(buf, str, -(1 as i32));
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufCCat(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut str: * const i8,
) -> i32 {
    return xmlBufCat(buf, str as *const xmlChar);
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufWriteQuotedString(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut string: * const u8,
) -> i32 {
    let mut cur: * const u8 = 0 as *const xmlChar;
    let mut base: * const u8 = 0 as *const xmlChar;
    if buf.is_null() || (*buf).error != 0 {
        return -(1 as i32);
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    if (*buf).alloc as u32
        == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
    {
        return -(1 as i32);
    }
    if !(xmlStrchr(string, '"' as i32 as xmlChar)).is_null() {
        if !(xmlStrchr(string, '\'' as i32 as xmlChar)).is_null() {
            xmlBufCCat(buf, b"\"\0" as *const u8 as *const i8);
            cur = string;
            base = cur;
            while *cur as i32 != 0 as i32 {
                if *cur as i32 == '"' as i32 {
                    if base != cur {
                        xmlBufAdd(
                            buf,
                            base,
                            cur.offset_from(base) as i64 as i32,
                        );
                    }
                    xmlBufAdd(
                        buf,
                        b"&quot;\0" as *const u8 as *const i8 as *mut xmlChar,
                        6 as i32,
                    );
                    cur = cur.offset(1);
                    base = cur;
                } else {
                    cur = cur.offset(1);
                }
            }
            if base != cur {
                xmlBufAdd(
                    buf,
                    base,
                    cur.offset_from(base) as i64 as i32,
                );
            }
            xmlBufCCat(buf, b"\"\0" as *const u8 as *const i8);
        } else {
            xmlBufCCat(buf, b"'\0" as *const u8 as *const i8);
            xmlBufCat(buf, string);
            xmlBufCCat(buf, b"'\0" as *const u8 as *const i8);
        }
    } else {
        xmlBufCCat(buf, b"\"\0" as *const u8 as *const i8);
        xmlBufCat(buf, string);
        xmlBufCCat(buf, b"\"\0" as *const u8 as *const i8);
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufFromBuffer(mut buffer: * mut crate::src::HTMLtree::_xmlBuffer) -> * mut crate::src::buf::_xmlBuf {
    let mut ret: * mut crate::src::buf::_xmlBuf = 0 as *mut xmlBuf;
    if buffer.is_null() {
        return 0 as xmlBufPtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlBuf>() as u64) as xmlBufPtr;
    if ret.is_null() {
        xmlBufMemoryError(
            0 as xmlBufPtr,
            b"creating buffer\0" as *const u8 as *const i8,
        );
        return 0 as xmlBufPtr;
    }
    (*ret).use_0 = (*buffer).use_0 as size_t;
    (*ret).size = (*buffer).size as size_t;
    if (*ret).size < 2147483647 as i32 as u64 {
        (*ret).compat_size = (*ret).size as u32;
    } else {
        (*ret).compat_size = 2147483647 as i32 as u32;
    }
    if (*ret).use_0 < 2147483647 as i32 as u64 {
        (*ret).compat_use = (*ret).use_0 as u32;
    } else {
        (*ret).compat_use = 2147483647 as i32 as u32;
    }
    (*ret).error = 0 as i32;
    let fresh29 = &mut ((*ret).buffer);
    *fresh29 = buffer;
    (*ret).alloc = (*buffer).alloc;
    let fresh30 = &mut ((*ret).content);
    *fresh30 = (*buffer).content;
    let fresh31 = &mut ((*ret).contentIO);
    *fresh31 = (*buffer).contentIO;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufBackToBuffer(mut buf: * mut crate::src::buf::_xmlBuf) -> * mut crate::src::HTMLtree::_xmlBuffer {
    let mut ret: * mut crate::src::HTMLtree::_xmlBuffer = 0 as *mut xmlBuffer;
    if buf.is_null() {
        return 0 as xmlBufferPtr;
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    if (*buf).error != 0 || ((*buf).buffer).is_null() {
        xmlBufFree(buf);
        return 0 as xmlBufferPtr;
    }
    ret = (*buf).buffer;
    if (*buf).use_0 > 2147483647 as i32 as u64 {
        xmlBufOverflowError(
            buf,
            b"Used size too big for xmlBuffer\0" as *const u8 as *const i8,
        );
        (*ret).use_0 = 2147483647 as i32 as u32;
        (*ret).size = 2147483647 as i32 as u32;
    } else if (*buf).size > 2147483647 as i32 as u64 {
        xmlBufOverflowError(
            buf,
            b"Allocated size too big for xmlBuffer\0" as *const u8 as *const i8,
        );
        (*ret).use_0 = (*buf).use_0 as i32 as u32;
        (*ret).size = 2147483647 as i32 as u32;
    } else {
        (*ret).use_0 = (*buf).use_0 as i32 as u32;
        (*ret).size = (*buf).size as i32 as u32;
    }
    (*ret).alloc = (*buf).alloc;
    let fresh32 = &mut ((*ret).content);
    *fresh32 = (*buf).content;
    let fresh33 = &mut ((*ret).contentIO);
    *fresh33 = (*buf).contentIO;
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufMergeBuffer(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut buffer: * mut crate::src::HTMLtree::_xmlBuffer,
) -> i32 {
    let mut ret: i32 = 0 as i32;
    if buf.is_null() || (*buf).error != 0 {
        xmlBufferFree(buffer);
        return -(1 as i32);
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    if !buffer.is_null() && !((*buffer).content).is_null()
        && (*buffer).use_0 > 0 as i32 as u32
    {
        ret = xmlBufAdd(buf, (*buffer).content, (*buffer).use_0 as i32);
    }
    xmlBufferFree(buffer);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufResetInput(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut input: * mut crate::src::HTMLparser::_xmlParserInput,
) -> i32 {
    if input.is_null() || buf.is_null() || (*buf).error != 0 {
        return -(1 as i32);
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    let fresh34 = &mut ((*input).cur);
    *fresh34 = (*buf).content;
    let fresh35 = &mut ((*input).base);
    *fresh35 = *fresh34;
    let fresh36 = &mut ((*input).end);
    *fresh36 = &mut *((*buf).content).offset((*buf).use_0 as isize) as *mut xmlChar;
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufGetInputBase(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut input: * mut crate::src::HTMLparser::_xmlParserInput,
) -> u64 {
    let mut base: u64 = 0;
    if input.is_null() || buf.is_null() || (*buf).error != 0 {
        return -(1 as i32) as size_t;
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    base = ((*input).base).offset_from((*buf).content) as i64 as size_t;
    if base > (*buf).size {
        xmlBufOverflowError(
            buf,
            b"Input reference outside of the buffer\0" as *const u8
                as *const i8,
        );
        base = 0 as i32 as size_t;
    }
    return base;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufSetInputBaseCur(
    mut buf: * mut crate::src::buf::_xmlBuf,
    mut input: * mut crate::src::HTMLparser::_xmlParserInput,
    mut base: u64,
    mut cur: u64,
) -> i32 {
    if input.is_null() {
        return -(1 as i32);
    }
    if buf.is_null() || (*buf).error != 0 {
        let fresh37 = &mut ((*input).end);
        *fresh37 = b"\0" as *const u8 as *const i8 as *mut xmlChar;
        let fresh38 = &mut ((*input).cur);
        *fresh38 = *fresh37;
        let fresh39 = &mut ((*input).base);
        *fresh39 = *fresh38;
        return -(1 as i32);
    }
    if (*buf).size != (*buf).compat_size as size_t {
        if (*buf).compat_size < 2147483647 as i32 as u32 {
            (*buf).size = (*buf).compat_size as size_t;
        }
    }
    if (*buf).use_0 != (*buf).compat_use as size_t {
        if (*buf).compat_use < 2147483647 as i32 as u32 {
            (*buf).use_0 = (*buf).compat_use as size_t;
        }
    }
    let fresh40 = &mut ((*input).base);
    *fresh40 = &mut *((*buf).content).offset(base as isize) as *mut xmlChar;
    let fresh41 = &mut ((*input).cur);
    *fresh41 = ((*input).base).offset(cur as isize);
    let fresh42 = &mut ((*input).end);
    *fresh42 = &mut *((*buf).content).offset((*buf).use_0 as isize) as *mut xmlChar;
    return 0 as i32;
}
use crate::laertes_rt::*;
