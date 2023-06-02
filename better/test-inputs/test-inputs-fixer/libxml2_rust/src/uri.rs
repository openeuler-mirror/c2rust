use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    fn xmlStrndup(cur: *const xmlChar, len: i32) -> *mut xmlChar;
    fn xmlStrchr(str: *const xmlChar, val: xmlChar) -> *const xmlChar;
    fn xmlStrstr(str: *const xmlChar, val: *const xmlChar) -> *const xmlChar;
    fn xmlStrcmp(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrlen(str: *const xmlChar) -> i32;
    fn xmlStrcat(cur: *mut xmlChar, add: *const xmlChar) -> *mut xmlChar;
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    fn snprintf(_: *mut i8, _: u64, _: *const i8, _: ...) -> i32;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn strlen(_: *const i8) -> u64;
    fn __xmlRaiseError(
        schannel: xmlStructuredErrorFunc,
        channel: xmlGenericErrorFunc,
        data: *mut libc::c_void,
        ctx: *mut libc::c_void,
        node: *mut libc::c_void,
        domain: i32,
        code: i32,
        level: xmlErrorLevel,
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
    static mut xmlMemStrdup: xmlStrdupFunc;
    static mut xmlFree: xmlFreeFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlMallocAtomic: xmlMallocFunc;
    static mut xmlMalloc: xmlMallocFunc;
}
pub type xmlChar = u8;
pub type size_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: i32,
    pub _IO_read_ptr: *mut i8,
    pub _IO_read_end: *mut i8,
    pub _IO_read_base: *mut i8,
    pub _IO_write_base: *mut i8,
    pub _IO_write_ptr: *mut i8,
    pub _IO_write_end: *mut i8,
    pub _IO_buf_base: *mut i8,
    pub _IO_buf_end: *mut i8,
    pub _IO_save_base: *mut i8,
    pub _IO_backup_base: *mut i8,
    pub _IO_save_end: *mut i8,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: i32,
    pub _flags2: i32,
    pub _old_offset: __off_t,
    pub _cur_column: u16,
    pub _vtable_offset: i8,
    pub _shortbuf: [i8; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: i32,
    pub _unused2: [i8; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type xmlReallocFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void>;
pub type xmlStrdupFunc = Option<unsafe extern "C" fn(*const i8) -> *mut i8>;
pub type xmlError = _xmlError;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlError {
    pub domain: i32,
    pub code: i32,
    pub message: *mut i8,
    pub level: xmlErrorLevel,
    pub file: *mut i8,
    pub line: i32,
    pub str1: *mut i8,
    pub str2: *mut i8,
    pub str3: *mut i8,
    pub int1: i32,
    pub int2: i32,
    pub ctxt: *mut libc::c_void,
    pub node: *mut libc::c_void,
}
pub type xmlErrorLevel = u32;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlStructuredErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> ()>;
pub type xmlErrorPtr = *mut xmlError;
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
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlURI {
    pub scheme: *mut i8,
    pub opaque: *mut i8,
    pub authority: *mut i8,
    pub server: *mut i8,
    pub user: *mut i8,
    pub port: i32,
    pub path: *mut i8,
    pub query: *mut i8,
    pub fragment: *mut i8,
    pub cleanup: i32,
    pub query_raw: *mut i8,
}
pub type xmlURI = _xmlURI;
pub type xmlURIPtr = *mut xmlURI;
extern "C" fn xmlURIErrMemory(mut extra: *const i8) {
    if !extra.is_null() {
        (unsafe { __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_URI as i32,
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
        ) });
    } else {
        (unsafe { __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_URI as i32,
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
        ) });
    };
}
extern "C" fn xmlParse3986Scheme(mut uri: xmlURIPtr, mut str: *mut *const i8) -> i32 {
    let mut cur: *const i8 = 0 as *const i8;
    if str.is_null() {
        return -(1 as i32);
    }
    cur = unsafe { *str };
    if !((unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
        || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32)
    {
        return 2 as i32;
    }
    cur = unsafe { cur.offset(1) };
    while (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
        || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
        || (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32
        || (unsafe { *cur }) as i32 == '+' as i32
        || (unsafe { *cur }) as i32 == '-' as i32
        || (unsafe { *cur }) as i32 == '.' as i32
    {
        cur = unsafe { cur.offset(1) };
    }
    if !uri.is_null() {
        if !(unsafe { (*uri).scheme }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*uri).scheme as *mut libc::c_void) });
        }
        let fresh0 = unsafe { &mut ((*uri).scheme) };
        *fresh0 =
            (unsafe { xmlStrndup(*str as *const xmlChar, cur.offset_from(*str) as i64 as i32) }) as *mut i8;
    }
    (unsafe { *str = cur });
    return 0 as i32;
}
extern "C" fn xmlParse3986Fragment(mut uri: xmlURIPtr, mut str: *mut *const i8) -> i32 {
    let mut cur: *const i8 = 0 as *const i8;
    if str.is_null() {
        return -(1 as i32);
    }
    cur = unsafe { *str };
    while (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
        || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
        || (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32
        || (unsafe { *cur }) as i32 == '-' as i32
        || (unsafe { *cur }) as i32 == '.' as i32
        || (unsafe { *cur }) as i32 == '_' as i32
        || (unsafe { *cur }) as i32 == '~' as i32
        || (unsafe { *cur }) as i32 == '%' as i32
            && ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= '9' as i32
                || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'a' as i32
                    && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'f' as i32
                || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'A' as i32
                    && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'F' as i32)
            && ((unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= '9' as i32
                || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'a' as i32
                    && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'f' as i32
                || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'A' as i32
                    && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'F' as i32)
        || ((unsafe { *cur }) as i32 == '!' as i32
            || (unsafe { *cur }) as i32 == '$' as i32
            || (unsafe { *cur }) as i32 == '&' as i32
            || (unsafe { *cur }) as i32 == '(' as i32
            || (unsafe { *cur }) as i32 == ')' as i32
            || (unsafe { *cur }) as i32 == '*' as i32
            || (unsafe { *cur }) as i32 == '+' as i32
            || (unsafe { *cur }) as i32 == ',' as i32
            || (unsafe { *cur }) as i32 == ';' as i32
            || (unsafe { *cur }) as i32 == '=' as i32
            || (unsafe { *cur }) as i32 == '\'' as i32)
        || (unsafe { *cur }) as i32 == ':' as i32
        || (unsafe { *cur }) as i32 == '@' as i32
        || (unsafe { *cur }) as i32 == '/' as i32
        || (unsafe { *cur }) as i32 == '?' as i32
        || (unsafe { *cur }) as i32 == '[' as i32
        || (unsafe { *cur }) as i32 == ']' as i32
        || !uri.is_null()
            && (unsafe { (*uri).cleanup }) & 1 as i32 != 0
            && ((unsafe { *cur }) as i32 == '{' as i32
                || (unsafe { *cur }) as i32 == '}' as i32
                || (unsafe { *cur }) as i32 == '|' as i32
                || (unsafe { *cur }) as i32 == '\\' as i32
                || (unsafe { *cur }) as i32 == '^' as i32
                || (unsafe { *cur }) as i32 == '[' as i32
                || (unsafe { *cur }) as i32 == ']' as i32
                || (unsafe { *cur }) as i32 == '`' as i32)
    {
        if (unsafe { *cur }) as i32 == '%' as i32 {
            cur = unsafe { cur.offset(3 as i32 as isize) };
        } else {
            cur = unsafe { cur.offset(1) };
        };
    }
    if !uri.is_null() {
        if !(unsafe { (*uri).fragment }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*uri).fragment as *mut libc::c_void) });
        }
        if (unsafe { (*uri).cleanup }) & 2 as i32 != 0 {
            let fresh1 = unsafe { &mut ((*uri).fragment) };
            *fresh1 =
                (unsafe { xmlStrndup(*str as *const xmlChar, cur.offset_from(*str) as i64 as i32) }) as *mut i8;
        } else {
            let fresh2 = unsafe { &mut ((*uri).fragment) };
            *fresh2 = xmlURIUnescapeString(unsafe { *str }, (unsafe { cur.offset_from(*str) }) as i64 as i32, 0 as *mut i8);
        }
    }
    (unsafe { *str = cur });
    return 0 as i32;
}
extern "C" fn xmlParse3986Query(mut uri: xmlURIPtr, mut str: *mut *const i8) -> i32 {
    let mut cur: *const i8 = 0 as *const i8;
    if str.is_null() {
        return -(1 as i32);
    }
    cur = unsafe { *str };
    while (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
        || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
        || (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32
        || (unsafe { *cur }) as i32 == '-' as i32
        || (unsafe { *cur }) as i32 == '.' as i32
        || (unsafe { *cur }) as i32 == '_' as i32
        || (unsafe { *cur }) as i32 == '~' as i32
        || (unsafe { *cur }) as i32 == '%' as i32
            && ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= '9' as i32
                || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'a' as i32
                    && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'f' as i32
                || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'A' as i32
                    && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'F' as i32)
            && ((unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= '9' as i32
                || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'a' as i32
                    && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'f' as i32
                || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'A' as i32
                    && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'F' as i32)
        || ((unsafe { *cur }) as i32 == '!' as i32
            || (unsafe { *cur }) as i32 == '$' as i32
            || (unsafe { *cur }) as i32 == '&' as i32
            || (unsafe { *cur }) as i32 == '(' as i32
            || (unsafe { *cur }) as i32 == ')' as i32
            || (unsafe { *cur }) as i32 == '*' as i32
            || (unsafe { *cur }) as i32 == '+' as i32
            || (unsafe { *cur }) as i32 == ',' as i32
            || (unsafe { *cur }) as i32 == ';' as i32
            || (unsafe { *cur }) as i32 == '=' as i32
            || (unsafe { *cur }) as i32 == '\'' as i32)
        || (unsafe { *cur }) as i32 == ':' as i32
        || (unsafe { *cur }) as i32 == '@' as i32
        || (unsafe { *cur }) as i32 == '/' as i32
        || (unsafe { *cur }) as i32 == '?' as i32
        || !uri.is_null()
            && (unsafe { (*uri).cleanup }) & 1 as i32 != 0
            && ((unsafe { *cur }) as i32 == '{' as i32
                || (unsafe { *cur }) as i32 == '}' as i32
                || (unsafe { *cur }) as i32 == '|' as i32
                || (unsafe { *cur }) as i32 == '\\' as i32
                || (unsafe { *cur }) as i32 == '^' as i32
                || (unsafe { *cur }) as i32 == '[' as i32
                || (unsafe { *cur }) as i32 == ']' as i32
                || (unsafe { *cur }) as i32 == '`' as i32)
    {
        if (unsafe { *cur }) as i32 == '%' as i32 {
            cur = unsafe { cur.offset(3 as i32 as isize) };
        } else {
            cur = unsafe { cur.offset(1) };
        };
    }
    if !uri.is_null() {
        if !(unsafe { (*uri).query }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*uri).query as *mut libc::c_void) });
        }
        if (unsafe { (*uri).cleanup }) & 2 as i32 != 0 {
            let fresh3 = unsafe { &mut ((*uri).query) };
            *fresh3 =
                (unsafe { xmlStrndup(*str as *const xmlChar, cur.offset_from(*str) as i64 as i32) }) as *mut i8;
        } else {
            let fresh4 = unsafe { &mut ((*uri).query) };
            *fresh4 = xmlURIUnescapeString(unsafe { *str }, (unsafe { cur.offset_from(*str) }) as i64 as i32, 0 as *mut i8);
        }
        if !(unsafe { (*uri).query_raw }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*uri).query_raw as *mut libc::c_void) });
        }
        let fresh5 = unsafe { &mut ((*uri).query_raw) };
        *fresh5 =
            (unsafe { xmlStrndup(*str as *const xmlChar, cur.offset_from(*str) as i64 as i32) }) as *mut i8;
    }
    (unsafe { *str = cur });
    return 0 as i32;
}
extern "C" fn xmlParse3986Port(mut uri: xmlURIPtr, mut str: *mut *const i8) -> i32 {
    let mut cur: *const i8 = unsafe { *str };
    let mut port: i32 = 0 as i32;
    if (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
        while (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
            let mut digit: i32 = (unsafe { *cur }) as i32 - '0' as i32;
            if port > 2147483647 as i32 / 10 as i32 {
                return 1 as i32;
            }
            port *= 10 as i32;
            if port > 2147483647 as i32 - digit {
                return 1 as i32;
            }
            port += digit;
            cur = unsafe { cur.offset(1) };
        }
        if !uri.is_null() {
            (unsafe { (*uri).port = port });
        }
        (unsafe { *str = cur });
        return 0 as i32;
    }
    return 1 as i32;
}
extern "C" fn xmlParse3986Userinfo(mut uri: xmlURIPtr, mut str: *mut *const i8) -> i32 {
    let mut cur: *const i8 = 0 as *const i8;
    cur = unsafe { *str };
    while (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
        || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
        || (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32
        || (unsafe { *cur }) as i32 == '-' as i32
        || (unsafe { *cur }) as i32 == '.' as i32
        || (unsafe { *cur }) as i32 == '_' as i32
        || (unsafe { *cur }) as i32 == '~' as i32
        || (unsafe { *cur }) as i32 == '%' as i32
            && ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= '9' as i32
                || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'a' as i32
                    && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'f' as i32
                || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'A' as i32
                    && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'F' as i32)
            && ((unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= '9' as i32
                || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'a' as i32
                    && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'f' as i32
                || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'A' as i32
                    && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'F' as i32)
        || ((unsafe { *cur }) as i32 == '!' as i32
            || (unsafe { *cur }) as i32 == '$' as i32
            || (unsafe { *cur }) as i32 == '&' as i32
            || (unsafe { *cur }) as i32 == '(' as i32
            || (unsafe { *cur }) as i32 == ')' as i32
            || (unsafe { *cur }) as i32 == '*' as i32
            || (unsafe { *cur }) as i32 == '+' as i32
            || (unsafe { *cur }) as i32 == ',' as i32
            || (unsafe { *cur }) as i32 == ';' as i32
            || (unsafe { *cur }) as i32 == '=' as i32
            || (unsafe { *cur }) as i32 == '\'' as i32)
        || (unsafe { *cur }) as i32 == ':' as i32
    {
        if (unsafe { *cur }) as i32 == '%' as i32 {
            cur = unsafe { cur.offset(3 as i32 as isize) };
        } else {
            cur = unsafe { cur.offset(1) };
        };
    }
    if (unsafe { *cur }) as i32 == '@' as i32 {
        if !uri.is_null() {
            if !(unsafe { (*uri).user }).is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")((*uri).user as *mut libc::c_void) });
            }
            if (unsafe { (*uri).cleanup }) & 2 as i32 != 0 {
                let fresh6 = unsafe { &mut ((*uri).user) };
                *fresh6 = (unsafe { xmlStrndup(*str as *const xmlChar, cur.offset_from(*str) as i64 as i32) })
                    as *mut i8;
            } else {
                let fresh7 = unsafe { &mut ((*uri).user) };
                *fresh7 =
                    xmlURIUnescapeString(unsafe { *str }, (unsafe { cur.offset_from(*str) }) as i64 as i32, 0 as *mut i8);
            }
        }
        (unsafe { *str = cur });
        return 0 as i32;
    }
    return 1 as i32;
}
extern "C" fn xmlParse3986DecOctet(mut str: *mut *const i8) -> i32 {
    let mut cur: *const i8 = unsafe { *str };
    if !((unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32) {
        return 1 as i32;
    }
    if !((unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= '0' as i32
        && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= '9' as i32)
    {
        cur = unsafe { cur.offset(1) };
    } else if (unsafe { *cur }) as i32 != '0' as i32
        && ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= '0' as i32
            && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= '9' as i32)
        && !((unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= '0' as i32
            && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= '9' as i32)
    {
        cur = unsafe { cur.offset(2 as i32 as isize) };
    } else if (unsafe { *cur }) as i32 == '1' as i32
        && ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= '0' as i32
            && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= '9' as i32)
        && ((unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= '0' as i32
            && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= '9' as i32)
    {
        cur = unsafe { cur.offset(3 as i32 as isize) };
    } else if (unsafe { *cur }) as i32 == '2' as i32
        && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= '0' as i32
        && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= '4' as i32
        && ((unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= '0' as i32
            && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= '9' as i32)
    {
        cur = unsafe { cur.offset(3 as i32 as isize) };
    } else if (unsafe { *cur }) as i32 == '2' as i32
        && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '5' as i32
        && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= '0' as i32
        && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= '5' as i32
    {
        cur = unsafe { cur.offset(3 as i32 as isize) };
    } else {
        return 1 as i32;
    }
    (unsafe { *str = cur });
    return 0 as i32;
}
extern "C" fn xmlParse3986Host(mut uri: xmlURIPtr, mut str: *mut *const i8) -> i32 {
    let mut current_block: u64;
    let mut cur: *const i8 = unsafe { *str };
    let mut host: *const i8 = 0 as *const i8;
    host = cur;
    if (unsafe { *cur }) as i32 == '[' as i32 {
        cur = unsafe { cur.offset(1) };
        while (unsafe { *cur }) as i32 != ']' as i32 && (unsafe { *cur }) as i32 != 0 as i32 {
            cur = unsafe { cur.offset(1) };
        }
        if (unsafe { *cur }) as i32 != ']' as i32 {
            return 1 as i32;
        }
        cur = unsafe { cur.offset(1) };
    } else {
        if (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
            if xmlParse3986DecOctet(&mut cur) != 0 as i32 {
                current_block = 6168486577495969577;
            } else if (unsafe { *cur }) as i32 != '.' as i32 {
                current_block = 6168486577495969577;
            } else {
                cur = unsafe { cur.offset(1) };
                if xmlParse3986DecOctet(&mut cur) != 0 as i32 {
                    current_block = 6168486577495969577;
                } else if (unsafe { *cur }) as i32 != '.' as i32 {
                    current_block = 6168486577495969577;
                } else if xmlParse3986DecOctet(&mut cur) != 0 as i32 {
                    current_block = 6168486577495969577;
                } else if (unsafe { *cur }) as i32 != '.' as i32 {
                    current_block = 6168486577495969577;
                } else if xmlParse3986DecOctet(&mut cur) != 0 as i32 {
                    current_block = 6168486577495969577;
                } else {
                    current_block = 2777664028896885676;
                }
            }
            match current_block {
                2777664028896885676 => {}
                _ => {
                    cur = unsafe { *str };
                    current_block = 5601891728916014340;
                }
            }
        } else {
            current_block = 5601891728916014340;
        }
        match current_block {
            2777664028896885676 => {}
            _ => {
                while (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
                    || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
                    || (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32
                    || (unsafe { *cur }) as i32 == '-' as i32
                    || (unsafe { *cur }) as i32 == '.' as i32
                    || (unsafe { *cur }) as i32 == '_' as i32
                    || (unsafe { *cur }) as i32 == '~' as i32
                    || (unsafe { *cur }) as i32 == '%' as i32
                        && ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= '0' as i32
                            && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= '9' as i32
                            || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'a' as i32
                                && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'f' as i32
                            || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'A' as i32
                                && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'F' as i32)
                        && ((unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= '0' as i32
                            && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= '9' as i32
                            || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'a' as i32
                                && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'f' as i32
                            || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'A' as i32
                                && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'F' as i32)
                    || ((unsafe { *cur }) as i32 == '!' as i32
                        || (unsafe { *cur }) as i32 == '$' as i32
                        || (unsafe { *cur }) as i32 == '&' as i32
                        || (unsafe { *cur }) as i32 == '(' as i32
                        || (unsafe { *cur }) as i32 == ')' as i32
                        || (unsafe { *cur }) as i32 == '*' as i32
                        || (unsafe { *cur }) as i32 == '+' as i32
                        || (unsafe { *cur }) as i32 == ',' as i32
                        || (unsafe { *cur }) as i32 == ';' as i32
                        || (unsafe { *cur }) as i32 == '=' as i32
                        || (unsafe { *cur }) as i32 == '\'' as i32)
                {
                    if (unsafe { *cur }) as i32 == '%' as i32 {
                        cur = unsafe { cur.offset(3 as i32 as isize) };
                    } else {
                        cur = unsafe { cur.offset(1) };
                    };
                }
            }
        }
    }
    if !uri.is_null() {
        if !(unsafe { (*uri).authority }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*uri).authority as *mut libc::c_void) });
        }
        let fresh8 = unsafe { &mut ((*uri).authority) };
        *fresh8 = 0 as *mut i8;
        if !(unsafe { (*uri).server }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*uri).server as *mut libc::c_void) });
        }
        if cur != host {
            if (unsafe { (*uri).cleanup }) & 2 as i32 != 0 {
                let fresh9 = unsafe { &mut ((*uri).server) };
                *fresh9 = (unsafe { xmlStrndup(host as *const xmlChar, cur.offset_from(host) as i64 as i32) })
                    as *mut i8;
            } else {
                let fresh10 = unsafe { &mut ((*uri).server) };
                *fresh10 =
                    xmlURIUnescapeString(host, (unsafe { cur.offset_from(host) }) as i64 as i32, 0 as *mut i8);
            }
        } else {
            let fresh11 = unsafe { &mut ((*uri).server) };
            *fresh11 = 0 as *mut i8;
        }
    }
    (unsafe { *str = cur });
    return 0 as i32;
}
extern "C" fn xmlParse3986Authority(mut uri: xmlURIPtr, mut str: *mut *const i8) -> i32 {
    let mut cur: *const i8 = 0 as *const i8;
    let mut ret: i32 = 0;
    cur = unsafe { *str };
    ret = xmlParse3986Userinfo(uri, &mut cur);
    if ret != 0 as i32 || (unsafe { *cur }) as i32 != '@' as i32 {
        cur = unsafe { *str };
    } else {
        cur = unsafe { cur.offset(1) };
    }
    ret = xmlParse3986Host(uri, &mut cur);
    if ret != 0 as i32 {
        return ret;
    }
    if (unsafe { *cur }) as i32 == ':' as i32 {
        cur = unsafe { cur.offset(1) };
        ret = xmlParse3986Port(uri, &mut cur);
        if ret != 0 as i32 {
            return ret;
        }
    }
    (unsafe { *str = cur });
    return 0 as i32;
}
extern "C" fn xmlParse3986Segment(mut str: *mut *const i8, mut forbid: i8, mut empty: i32) -> i32 {
    let mut cur: *const i8 = 0 as *const i8;
    cur = unsafe { *str };
    if !((unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
        || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
        || (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32
        || (unsafe { *cur }) as i32 == '-' as i32
        || (unsafe { *cur }) as i32 == '.' as i32
        || (unsafe { *cur }) as i32 == '_' as i32
        || (unsafe { *cur }) as i32 == '~' as i32
        || (unsafe { *cur }) as i32 == '%' as i32
            && ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= '9' as i32
                || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'a' as i32
                    && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'f' as i32
                || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'A' as i32
                    && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'F' as i32)
            && ((unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= '9' as i32
                || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'a' as i32
                    && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'f' as i32
                || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'A' as i32
                    && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'F' as i32)
        || ((unsafe { *cur }) as i32 == '!' as i32
            || (unsafe { *cur }) as i32 == '$' as i32
            || (unsafe { *cur }) as i32 == '&' as i32
            || (unsafe { *cur }) as i32 == '(' as i32
            || (unsafe { *cur }) as i32 == ')' as i32
            || (unsafe { *cur }) as i32 == '*' as i32
            || (unsafe { *cur }) as i32 == '+' as i32
            || (unsafe { *cur }) as i32 == ',' as i32
            || (unsafe { *cur }) as i32 == ';' as i32
            || (unsafe { *cur }) as i32 == '=' as i32
            || (unsafe { *cur }) as i32 == '\'' as i32)
        || (unsafe { *cur }) as i32 == ':' as i32
        || (unsafe { *cur }) as i32 == '@' as i32)
    {
        if empty != 0 {
            return 0 as i32;
        }
        return 1 as i32;
    }
    while ((unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
        || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
        || (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32
        || (unsafe { *cur }) as i32 == '-' as i32
        || (unsafe { *cur }) as i32 == '.' as i32
        || (unsafe { *cur }) as i32 == '_' as i32
        || (unsafe { *cur }) as i32 == '~' as i32
        || (unsafe { *cur }) as i32 == '%' as i32
            && ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= '9' as i32
                || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'a' as i32
                    && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'f' as i32
                || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'A' as i32
                    && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'F' as i32)
            && ((unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= '9' as i32
                || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'a' as i32
                    && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'f' as i32
                || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'A' as i32
                    && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'F' as i32)
        || ((unsafe { *cur }) as i32 == '!' as i32
            || (unsafe { *cur }) as i32 == '$' as i32
            || (unsafe { *cur }) as i32 == '&' as i32
            || (unsafe { *cur }) as i32 == '(' as i32
            || (unsafe { *cur }) as i32 == ')' as i32
            || (unsafe { *cur }) as i32 == '*' as i32
            || (unsafe { *cur }) as i32 == '+' as i32
            || (unsafe { *cur }) as i32 == ',' as i32
            || (unsafe { *cur }) as i32 == ';' as i32
            || (unsafe { *cur }) as i32 == '=' as i32
            || (unsafe { *cur }) as i32 == '\'' as i32)
        || (unsafe { *cur }) as i32 == ':' as i32
        || (unsafe { *cur }) as i32 == '@' as i32)
        && (unsafe { *cur }) as i32 != forbid as i32
    {
        if (unsafe { *cur }) as i32 == '%' as i32 {
            cur = unsafe { cur.offset(3 as i32 as isize) };
        } else {
            cur = unsafe { cur.offset(1) };
        };
    }
    (unsafe { *str = cur });
    return 0 as i32;
}
extern "C" fn xmlParse3986PathAbEmpty(mut uri: xmlURIPtr, mut str: *mut *const i8) -> i32 {
    let mut cur: *const i8 = 0 as *const i8;
    let mut ret: i32 = 0;
    cur = unsafe { *str };
    while (unsafe { *cur }) as i32 == '/' as i32 {
        cur = unsafe { cur.offset(1) };
        ret = xmlParse3986Segment(&mut cur, 0 as i32 as i8, 1 as i32);
        if ret != 0 as i32 {
            return ret;
        }
    }
    if !uri.is_null() {
        if !(unsafe { (*uri).path }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*uri).path as *mut libc::c_void) });
        }
        if (unsafe { *str }) != cur {
            if (unsafe { (*uri).cleanup }) & 2 as i32 != 0 {
                let fresh12 = unsafe { &mut ((*uri).path) };
                *fresh12 = (unsafe { xmlStrndup(*str as *const xmlChar, cur.offset_from(*str) as i64 as i32) })
                    as *mut i8;
            } else {
                let fresh13 = unsafe { &mut ((*uri).path) };
                *fresh13 =
                    xmlURIUnescapeString(unsafe { *str }, (unsafe { cur.offset_from(*str) }) as i64 as i32, 0 as *mut i8);
            }
        } else {
            let fresh14 = unsafe { &mut ((*uri).path) };
            *fresh14 = 0 as *mut i8;
        }
    }
    (unsafe { *str = cur });
    return 0 as i32;
}
extern "C" fn xmlParse3986PathAbsolute(mut uri: xmlURIPtr, mut str: *mut *const i8) -> i32 {
    let mut cur: *const i8 = 0 as *const i8;
    let mut ret: i32 = 0;
    cur = unsafe { *str };
    if (unsafe { *cur }) as i32 != '/' as i32 {
        return 1 as i32;
    }
    cur = unsafe { cur.offset(1) };
    ret = xmlParse3986Segment(&mut cur, 0 as i32 as i8, 0 as i32);
    if ret == 0 as i32 {
        while (unsafe { *cur }) as i32 == '/' as i32 {
            cur = unsafe { cur.offset(1) };
            ret = xmlParse3986Segment(&mut cur, 0 as i32 as i8, 1 as i32);
            if ret != 0 as i32 {
                return ret;
            }
        }
    }
    if !uri.is_null() {
        if !(unsafe { (*uri).path }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*uri).path as *mut libc::c_void) });
        }
        if cur != (unsafe { *str }) {
            if (unsafe { (*uri).cleanup }) & 2 as i32 != 0 {
                let fresh15 = unsafe { &mut ((*uri).path) };
                *fresh15 = (unsafe { xmlStrndup(*str as *const xmlChar, cur.offset_from(*str) as i64 as i32) })
                    as *mut i8;
            } else {
                let fresh16 = unsafe { &mut ((*uri).path) };
                *fresh16 =
                    xmlURIUnescapeString(unsafe { *str }, (unsafe { cur.offset_from(*str) }) as i64 as i32, 0 as *mut i8);
            }
        } else {
            let fresh17 = unsafe { &mut ((*uri).path) };
            *fresh17 = 0 as *mut i8;
        }
    }
    (unsafe { *str = cur });
    return 0 as i32;
}
extern "C" fn xmlParse3986PathRootless(mut uri: xmlURIPtr, mut str: *mut *const i8) -> i32 {
    let mut cur: *const i8 = 0 as *const i8;
    let mut ret: i32 = 0;
    cur = unsafe { *str };
    ret = xmlParse3986Segment(&mut cur, 0 as i32 as i8, 0 as i32);
    if ret != 0 as i32 {
        return ret;
    }
    while (unsafe { *cur }) as i32 == '/' as i32 {
        cur = unsafe { cur.offset(1) };
        ret = xmlParse3986Segment(&mut cur, 0 as i32 as i8, 1 as i32);
        if ret != 0 as i32 {
            return ret;
        }
    }
    if !uri.is_null() {
        if !(unsafe { (*uri).path }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*uri).path as *mut libc::c_void) });
        }
        if cur != (unsafe { *str }) {
            if (unsafe { (*uri).cleanup }) & 2 as i32 != 0 {
                let fresh18 = unsafe { &mut ((*uri).path) };
                *fresh18 = (unsafe { xmlStrndup(*str as *const xmlChar, cur.offset_from(*str) as i64 as i32) })
                    as *mut i8;
            } else {
                let fresh19 = unsafe { &mut ((*uri).path) };
                *fresh19 =
                    xmlURIUnescapeString(unsafe { *str }, (unsafe { cur.offset_from(*str) }) as i64 as i32, 0 as *mut i8);
            }
        } else {
            let fresh20 = unsafe { &mut ((*uri).path) };
            *fresh20 = 0 as *mut i8;
        }
    }
    (unsafe { *str = cur });
    return 0 as i32;
}
extern "C" fn xmlParse3986PathNoScheme(mut uri: xmlURIPtr, mut str: *mut *const i8) -> i32 {
    let mut cur: *const i8 = 0 as *const i8;
    let mut ret: i32 = 0;
    cur = unsafe { *str };
    ret = xmlParse3986Segment(&mut cur, ':' as i32 as i8, 0 as i32);
    if ret != 0 as i32 {
        return ret;
    }
    while (unsafe { *cur }) as i32 == '/' as i32 {
        cur = unsafe { cur.offset(1) };
        ret = xmlParse3986Segment(&mut cur, 0 as i32 as i8, 1 as i32);
        if ret != 0 as i32 {
            return ret;
        }
    }
    if !uri.is_null() {
        if !(unsafe { (*uri).path }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*uri).path as *mut libc::c_void) });
        }
        if cur != (unsafe { *str }) {
            if (unsafe { (*uri).cleanup }) & 2 as i32 != 0 {
                let fresh21 = unsafe { &mut ((*uri).path) };
                *fresh21 = (unsafe { xmlStrndup(*str as *const xmlChar, cur.offset_from(*str) as i64 as i32) })
                    as *mut i8;
            } else {
                let fresh22 = unsafe { &mut ((*uri).path) };
                *fresh22 =
                    xmlURIUnescapeString(unsafe { *str }, (unsafe { cur.offset_from(*str) }) as i64 as i32, 0 as *mut i8);
            }
        } else {
            let fresh23 = unsafe { &mut ((*uri).path) };
            *fresh23 = 0 as *mut i8;
        }
    }
    (unsafe { *str = cur });
    return 0 as i32;
}
extern "C" fn xmlParse3986HierPart(mut uri: xmlURIPtr, mut str: *mut *const i8) -> i32 {
    let mut cur: *const i8 = 0 as *const i8;
    let mut ret: i32 = 0;
    cur = unsafe { *str };
    if (unsafe { *cur }) as i32 == '/' as i32 && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '/' as i32 {
        cur = unsafe { cur.offset(2 as i32 as isize) };
        ret = xmlParse3986Authority(uri, &mut cur);
        if ret != 0 as i32 {
            return ret;
        }
        if (unsafe { (*uri).server }).is_null() {
            (unsafe { (*uri).port = -(1 as i32) });
        }
        ret = xmlParse3986PathAbEmpty(uri, &mut cur);
        if ret != 0 as i32 {
            return ret;
        }
        (unsafe { *str = cur });
        return 0 as i32;
    } else {
        if (unsafe { *cur }) as i32 == '/' as i32 {
            ret = xmlParse3986PathAbsolute(uri, &mut cur);
            if ret != 0 as i32 {
                return ret;
            }
        } else if (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
            || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
            || (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32
            || (unsafe { *cur }) as i32 == '-' as i32
            || (unsafe { *cur }) as i32 == '.' as i32
            || (unsafe { *cur }) as i32 == '_' as i32
            || (unsafe { *cur }) as i32 == '~' as i32
            || (unsafe { *cur }) as i32 == '%' as i32
                && ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= '0' as i32
                    && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= '9' as i32
                    || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'a' as i32
                        && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'f' as i32
                    || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 >= 'A' as i32
                        && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 <= 'F' as i32)
                && ((unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= '0' as i32
                    && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= '9' as i32
                    || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'a' as i32
                        && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'f' as i32
                    || (unsafe { *cur.offset(2 as i32 as isize) }) as i32 >= 'A' as i32
                        && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 <= 'F' as i32)
            || ((unsafe { *cur }) as i32 == '!' as i32
                || (unsafe { *cur }) as i32 == '$' as i32
                || (unsafe { *cur }) as i32 == '&' as i32
                || (unsafe { *cur }) as i32 == '(' as i32
                || (unsafe { *cur }) as i32 == ')' as i32
                || (unsafe { *cur }) as i32 == '*' as i32
                || (unsafe { *cur }) as i32 == '+' as i32
                || (unsafe { *cur }) as i32 == ',' as i32
                || (unsafe { *cur }) as i32 == ';' as i32
                || (unsafe { *cur }) as i32 == '=' as i32
                || (unsafe { *cur }) as i32 == '\'' as i32)
            || (unsafe { *cur }) as i32 == ':' as i32
            || (unsafe { *cur }) as i32 == '@' as i32
        {
            ret = xmlParse3986PathRootless(uri, &mut cur);
            if ret != 0 as i32 {
                return ret;
            }
        } else if !uri.is_null() {
            if !(unsafe { (*uri).path }).is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")((*uri).path as *mut libc::c_void) });
            }
            let fresh24 = unsafe { &mut ((*uri).path) };
            *fresh24 = 0 as *mut i8;
        }
    }
    (unsafe { *str = cur });
    return 0 as i32;
}
extern "C" fn xmlParse3986RelativeRef(mut uri: xmlURIPtr, mut str: *const i8) -> i32 {
    let mut ret: i32 = 0;
    if (unsafe { *str }) as i32 == '/' as i32 && (unsafe { *str.offset(1 as i32 as isize) }) as i32 == '/' as i32 {
        str = unsafe { str.offset(2 as i32 as isize) };
        ret = xmlParse3986Authority(uri, &mut str);
        if ret != 0 as i32 {
            return ret;
        }
        ret = xmlParse3986PathAbEmpty(uri, &mut str);
        if ret != 0 as i32 {
            return ret;
        }
    } else if (unsafe { *str }) as i32 == '/' as i32 {
        ret = xmlParse3986PathAbsolute(uri, &mut str);
        if ret != 0 as i32 {
            return ret;
        }
    } else if (unsafe { *str }) as i32 >= 'a' as i32 && (unsafe { *str }) as i32 <= 'z' as i32
        || (unsafe { *str }) as i32 >= 'A' as i32 && (unsafe { *str }) as i32 <= 'Z' as i32
        || (unsafe { *str }) as i32 >= '0' as i32 && (unsafe { *str }) as i32 <= '9' as i32
        || (unsafe { *str }) as i32 == '-' as i32
        || (unsafe { *str }) as i32 == '.' as i32
        || (unsafe { *str }) as i32 == '_' as i32
        || (unsafe { *str }) as i32 == '~' as i32
        || (unsafe { *str }) as i32 == '%' as i32
            && ((unsafe { *str.offset(1 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *str.offset(1 as i32 as isize) }) as i32 <= '9' as i32
                || (unsafe { *str.offset(1 as i32 as isize) }) as i32 >= 'a' as i32
                    && (unsafe { *str.offset(1 as i32 as isize) }) as i32 <= 'f' as i32
                || (unsafe { *str.offset(1 as i32 as isize) }) as i32 >= 'A' as i32
                    && (unsafe { *str.offset(1 as i32 as isize) }) as i32 <= 'F' as i32)
            && ((unsafe { *str.offset(2 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *str.offset(2 as i32 as isize) }) as i32 <= '9' as i32
                || (unsafe { *str.offset(2 as i32 as isize) }) as i32 >= 'a' as i32
                    && (unsafe { *str.offset(2 as i32 as isize) }) as i32 <= 'f' as i32
                || (unsafe { *str.offset(2 as i32 as isize) }) as i32 >= 'A' as i32
                    && (unsafe { *str.offset(2 as i32 as isize) }) as i32 <= 'F' as i32)
        || ((unsafe { *str }) as i32 == '!' as i32
            || (unsafe { *str }) as i32 == '$' as i32
            || (unsafe { *str }) as i32 == '&' as i32
            || (unsafe { *str }) as i32 == '(' as i32
            || (unsafe { *str }) as i32 == ')' as i32
            || (unsafe { *str }) as i32 == '*' as i32
            || (unsafe { *str }) as i32 == '+' as i32
            || (unsafe { *str }) as i32 == ',' as i32
            || (unsafe { *str }) as i32 == ';' as i32
            || (unsafe { *str }) as i32 == '=' as i32
            || (unsafe { *str }) as i32 == '\'' as i32)
        || (unsafe { *str }) as i32 == ':' as i32
        || (unsafe { *str }) as i32 == '@' as i32
    {
        ret = xmlParse3986PathNoScheme(uri, &mut str);
        if ret != 0 as i32 {
            return ret;
        }
    } else if !uri.is_null() {
        if !(unsafe { (*uri).path }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*uri).path as *mut libc::c_void) });
        }
        let fresh25 = unsafe { &mut ((*uri).path) };
        *fresh25 = 0 as *mut i8;
    }
    if (unsafe { *str }) as i32 == '?' as i32 {
        str = unsafe { str.offset(1) };
        ret = xmlParse3986Query(uri, &mut str);
        if ret != 0 as i32 {
            return ret;
        }
    }
    if (unsafe { *str }) as i32 == '#' as i32 {
        str = unsafe { str.offset(1) };
        ret = xmlParse3986Fragment(uri, &mut str);
        if ret != 0 as i32 {
            return ret;
        }
    }
    if (unsafe { *str }) as i32 != 0 as i32 {
        xmlCleanURI(uri);
        return 1 as i32;
    }
    return 0 as i32;
}
extern "C" fn xmlParse3986URI(mut uri: xmlURIPtr, mut str: *const i8) -> i32 {
    let mut ret: i32 = 0;
    ret = xmlParse3986Scheme(uri, &mut str);
    if ret != 0 as i32 {
        return ret;
    }
    if (unsafe { *str }) as i32 != ':' as i32 {
        return 1 as i32;
    }
    str = unsafe { str.offset(1) };
    ret = xmlParse3986HierPart(uri, &mut str);
    if ret != 0 as i32 {
        return ret;
    }
    if (unsafe { *str }) as i32 == '?' as i32 {
        str = unsafe { str.offset(1) };
        ret = xmlParse3986Query(uri, &mut str);
        if ret != 0 as i32 {
            return ret;
        }
    }
    if (unsafe { *str }) as i32 == '#' as i32 {
        str = unsafe { str.offset(1) };
        ret = xmlParse3986Fragment(uri, &mut str);
        if ret != 0 as i32 {
            return ret;
        }
    }
    if (unsafe { *str }) as i32 != 0 as i32 {
        xmlCleanURI(uri);
        return 1 as i32;
    }
    return 0 as i32;
}
extern "C" fn xmlParse3986URIReference(mut uri: xmlURIPtr, mut str: *const i8) -> i32 {
    let mut ret: i32 = 0;
    if str.is_null() {
        return -(1 as i32);
    }
    xmlCleanURI(uri);
    ret = xmlParse3986URI(uri, str);
    if ret != 0 as i32 {
        xmlCleanURI(uri);
        ret = xmlParse3986RelativeRef(uri, str);
        if ret != 0 as i32 {
            xmlCleanURI(uri);
            return ret;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlParseURI(mut str: *const i8) -> xmlURIPtr {
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut ret: i32 = 0;
    if str.is_null() {
        return 0 as xmlURIPtr;
    }
    uri = xmlCreateURI();
    if !uri.is_null() {
        ret = xmlParse3986URIReference(uri, str);
        if ret != 0 {
            xmlFreeURI(uri);
            return 0 as xmlURIPtr;
        }
    }
    return uri;
}
#[no_mangle]
pub extern "C" fn xmlParseURIReference(mut uri: xmlURIPtr, mut str: *const i8) -> i32 {
    return xmlParse3986URIReference(uri, str);
}
#[no_mangle]
pub extern "C" fn xmlParseURIRaw(mut str: *const i8, mut raw: i32) -> xmlURIPtr {
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut ret: i32 = 0;
    if str.is_null() {
        return 0 as xmlURIPtr;
    }
    uri = xmlCreateURI();
    if !uri.is_null() {
        if raw != 0 {
            (unsafe { (*uri).cleanup |= 2 as i32 });
        }
        ret = xmlParseURIReference(uri, str);
        if ret != 0 {
            xmlFreeURI(uri);
            return 0 as xmlURIPtr;
        }
    }
    return uri;
}
#[no_mangle]
pub extern "C" fn xmlCreateURI() -> xmlURIPtr {
    let mut ret: xmlURIPtr = 0 as *mut xmlURI;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlURI>() as u64) })
        as xmlURIPtr;
    if ret.is_null() {
        xmlURIErrMemory(b"creating URI structure\n\0" as *const u8 as *const i8);
        return 0 as xmlURIPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlURI>() as u64,
    ) });
    return ret;
}
extern "C" fn xmlSaveUriRealloc(mut ret: *mut xmlChar, mut max: *mut i32) -> *mut xmlChar {
    let mut temp: *mut xmlChar = 0 as *mut xmlChar;
    let mut tmp: i32 = 0;
    if (unsafe { *max }) > 1024 as i32 * 1024 as i32 {
        xmlURIErrMemory(b"reaching arbitrary MAX_URI_LENGTH limit\n\0" as *const u8 as *const i8);
        return 0 as *mut xmlChar;
    }
    tmp = (unsafe { *max }) * 2 as i32;
    temp = (unsafe { xmlRealloc.expect("non-null function pointer")(
        ret as *mut libc::c_void,
        (tmp + 1 as i32) as size_t,
    ) }) as *mut xmlChar;
    if temp.is_null() {
        xmlURIErrMemory(b"saving URI\n\0" as *const u8 as *const i8);
        return 0 as *mut xmlChar;
    }
    (unsafe { *max = tmp });
    return temp;
}
#[no_mangle]
pub extern "C" fn xmlSaveUri(mut uri: xmlURIPtr) -> *mut xmlChar {
    let mut current_block: u64;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut temp: *mut xmlChar = 0 as *mut xmlChar;
    let mut p: *const i8 = 0 as *const i8;
    let mut len: i32 = 0;
    let mut max: i32 = 0;
    if uri.is_null() {
        return 0 as *mut xmlChar;
    }
    max = 80 as i32;
    ret = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
        ((max + 1 as i32) as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) }) as *mut xmlChar;
    if ret.is_null() {
        xmlURIErrMemory(b"saving URI\n\0" as *const u8 as *const i8);
        return 0 as *mut xmlChar;
    }
    len = 0 as i32;
    if !(unsafe { (*uri).scheme }).is_null() {
        p = unsafe { (*uri).scheme };
        loop {
            if !((unsafe { *p }) as i32 != 0 as i32) {
                current_block = 15904375183555213903;
                break;
            }
            if len >= max {
                temp = xmlSaveUriRealloc(ret, &mut max);
                if temp.is_null() {
                    current_block = 18064673131860544307;
                    break;
                }
                ret = temp;
            }
            let fresh26 = p;
            p = unsafe { p.offset(1) };
            let fresh27 = len;
            len = len + 1;
            (unsafe { *ret.offset(fresh27 as isize) = *fresh26 as xmlChar });
        }
        match current_block {
            18064673131860544307 => {}
            _ => {
                if len >= max {
                    temp = xmlSaveUriRealloc(ret, &mut max);
                    if temp.is_null() {
                        current_block = 18064673131860544307;
                    } else {
                        ret = temp;
                        current_block = 14401909646449704462;
                    }
                } else {
                    current_block = 14401909646449704462;
                }
                match current_block {
                    18064673131860544307 => {}
                    _ => {
                        let fresh28 = len;
                        len = len + 1;
                        (unsafe { *ret.offset(fresh28 as isize) = ':' as i32 as xmlChar });
                        current_block = 17478428563724192186;
                    }
                }
            }
        }
    } else {
        current_block = 17478428563724192186;
    }
    match current_block {
        17478428563724192186 => {
            if !(unsafe { (*uri).opaque }).is_null() {
                p = unsafe { (*uri).opaque };
                loop {
                    if !((unsafe { *p }) as i32 != 0 as i32) {
                        current_block = 13161952823003036500;
                        break;
                    }
                    if len + 3 as i32 >= max {
                        temp = xmlSaveUriRealloc(ret, &mut max);
                        if temp.is_null() {
                            current_block = 18064673131860544307;
                            break;
                        }
                        ret = temp;
                    }
                    if (unsafe { *p }) as i32 == ';' as i32
                        || (unsafe { *p }) as i32 == '/' as i32
                        || (unsafe { *p }) as i32 == '?' as i32
                        || (unsafe { *p }) as i32 == ':' as i32
                        || (unsafe { *p }) as i32 == '@' as i32
                        || (unsafe { *p }) as i32 == '&' as i32
                        || (unsafe { *p }) as i32 == '=' as i32
                        || (unsafe { *p }) as i32 == '+' as i32
                        || (unsafe { *p }) as i32 == '$' as i32
                        || (unsafe { *p }) as i32 == ',' as i32
                        || (unsafe { *p }) as i32 == '[' as i32
                        || (unsafe { *p }) as i32 == ']' as i32
                        || ((unsafe { *p }) as i32 >= 'a' as i32 && (unsafe { *p }) as i32 <= 'z' as i32
                            || (unsafe { *p }) as i32 >= 'A' as i32 && (unsafe { *p }) as i32 <= 'Z' as i32
                            || (unsafe { *p }) as i32 >= '0' as i32 && (unsafe { *p }) as i32 <= '9' as i32
                            || ((unsafe { *p }) as i32 == '-' as i32
                                || (unsafe { *p }) as i32 == '_' as i32
                                || (unsafe { *p }) as i32 == '.' as i32
                                || (unsafe { *p }) as i32 == '!' as i32
                                || (unsafe { *p }) as i32 == '~' as i32
                                || (unsafe { *p }) as i32 == '*' as i32
                                || (unsafe { *p }) as i32 == '\'' as i32
                                || (unsafe { *p }) as i32 == '(' as i32
                                || (unsafe { *p }) as i32 == ')' as i32))
                    {
                        let fresh29 = p;
                        p = unsafe { p.offset(1) };
                        let fresh30 = len;
                        len = len + 1;
                        (unsafe { *ret.offset(fresh30 as isize) = *fresh29 as xmlChar });
                    } else {
                        let fresh31 = p;
                        p = unsafe { p.offset(1) };
                        let mut val: i32 = (unsafe { *(fresh31 as *mut u8) }) as i32;
                        let mut hi: i32 = val / 0x10 as i32;
                        let mut lo: i32 = val % 0x10 as i32;
                        let fresh32 = len;
                        len = len + 1;
                        (unsafe { *ret.offset(fresh32 as isize) = '%' as i32 as xmlChar });
                        let fresh33 = len;
                        len = len + 1;
                        (unsafe { *ret.offset(fresh33 as isize) = (hi
                            + (if hi > 9 as i32 {
                                'A' as i32 - 10 as i32
                            } else {
                                '0' as i32
                            })) as xmlChar });
                        let fresh34 = len;
                        len = len + 1;
                        (unsafe { *ret.offset(fresh34 as isize) = (lo
                            + (if lo > 9 as i32 {
                                'A' as i32 - 10 as i32
                            } else {
                                '0' as i32
                            })) as xmlChar });
                    }
                }
            } else {
                if !(unsafe { (*uri).server }).is_null() || (unsafe { (*uri).port }) == -(1 as i32) {
                    if len + 3 as i32 >= max {
                        temp = xmlSaveUriRealloc(ret, &mut max);
                        if temp.is_null() {
                            current_block = 18064673131860544307;
                        } else {
                            ret = temp;
                            current_block = 9441801433784995173;
                        }
                    } else {
                        current_block = 9441801433784995173;
                    }
                    match current_block {
                        18064673131860544307 => {}
                        _ => {
                            let fresh35 = len;
                            len = len + 1;
                            (unsafe { *ret.offset(fresh35 as isize) = '/' as i32 as xmlChar });
                            let fresh36 = len;
                            len = len + 1;
                            (unsafe { *ret.offset(fresh36 as isize) = '/' as i32 as xmlChar });
                            if !(unsafe { (*uri).user }).is_null() {
                                p = unsafe { (*uri).user };
                                loop {
                                    if !((unsafe { *p }) as i32 != 0 as i32) {
                                        current_block = 8835654301469918283;
                                        break;
                                    }
                                    if len + 3 as i32 >= max {
                                        temp = xmlSaveUriRealloc(ret, &mut max);
                                        if temp.is_null() {
                                            current_block = 18064673131860544307;
                                            break;
                                        }
                                        ret = temp;
                                    }
                                    if (unsafe { *p }) as i32 >= 'a' as i32 && (unsafe { *p }) as i32 <= 'z' as i32
                                        || (unsafe { *p }) as i32 >= 'A' as i32 && (unsafe { *p }) as i32 <= 'Z' as i32
                                        || (unsafe { *p }) as i32 >= '0' as i32 && (unsafe { *p }) as i32 <= '9' as i32
                                        || ((unsafe { *p }) as i32 == '-' as i32
                                            || (unsafe { *p }) as i32 == '_' as i32
                                            || (unsafe { *p }) as i32 == '.' as i32
                                            || (unsafe { *p }) as i32 == '!' as i32
                                            || (unsafe { *p }) as i32 == '~' as i32
                                            || (unsafe { *p }) as i32 == '*' as i32
                                            || (unsafe { *p }) as i32 == '\'' as i32
                                            || (unsafe { *p }) as i32 == '(' as i32
                                            || (unsafe { *p }) as i32 == ')' as i32)
                                        || (unsafe { *p }) as i32 == ';' as i32
                                        || (unsafe { *p }) as i32 == ':' as i32
                                        || (unsafe { *p }) as i32 == '&' as i32
                                        || (unsafe { *p }) as i32 == '=' as i32
                                        || (unsafe { *p }) as i32 == '+' as i32
                                        || (unsafe { *p }) as i32 == '$' as i32
                                        || (unsafe { *p }) as i32 == ',' as i32
                                    {
                                        let fresh37 = p;
                                        p = unsafe { p.offset(1) };
                                        let fresh38 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh38 as isize) = *fresh37 as xmlChar });
                                    } else {
                                        let fresh39 = p;
                                        p = unsafe { p.offset(1) };
                                        let mut val_0: i32 = (unsafe { *(fresh39 as *mut u8) }) as i32;
                                        let mut hi_0: i32 = val_0 / 0x10 as i32;
                                        let mut lo_0: i32 = val_0 % 0x10 as i32;
                                        let fresh40 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh40 as isize) = '%' as i32 as xmlChar });
                                        let fresh41 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh41 as isize) = (hi_0
                                            + (if hi_0 > 9 as i32 {
                                                'A' as i32 - 10 as i32
                                            } else {
                                                '0' as i32
                                            }))
                                            as xmlChar });
                                        let fresh42 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh42 as isize) = (lo_0
                                            + (if lo_0 > 9 as i32 {
                                                'A' as i32 - 10 as i32
                                            } else {
                                                '0' as i32
                                            }))
                                            as xmlChar });
                                    }
                                }
                                match current_block {
                                    18064673131860544307 => {}
                                    _ => {
                                        if len + 3 as i32 >= max {
                                            temp = xmlSaveUriRealloc(ret, &mut max);
                                            if temp.is_null() {
                                                current_block = 18064673131860544307;
                                            } else {
                                                ret = temp;
                                                current_block = 307447392441238883;
                                            }
                                        } else {
                                            current_block = 307447392441238883;
                                        }
                                        match current_block {
                                            18064673131860544307 => {}
                                            _ => {
                                                let fresh43 = len;
                                                len = len + 1;
                                                (unsafe { *ret.offset(fresh43 as isize) =
                                                    '@' as i32 as xmlChar });
                                                current_block = 15970011996474399071;
                                            }
                                        }
                                    }
                                }
                            } else {
                                current_block = 15970011996474399071;
                            }
                            match current_block {
                                18064673131860544307 => {}
                                _ => {
                                    if !(unsafe { (*uri).server }).is_null() {
                                        p = unsafe { (*uri).server };
                                        loop {
                                            if !((unsafe { *p }) as i32 != 0 as i32) {
                                                current_block = 3736434875406665187;
                                                break;
                                            }
                                            if len >= max {
                                                temp = xmlSaveUriRealloc(ret, &mut max);
                                                if temp.is_null() {
                                                    current_block = 18064673131860544307;
                                                    break;
                                                }
                                                ret = temp;
                                            }
                                            let fresh44 = p;
                                            p = unsafe { p.offset(1) };
                                            let fresh45 = len;
                                            len = len + 1;
                                            (unsafe { *ret.offset(fresh45 as isize) = *fresh44 as xmlChar });
                                        }
                                        match current_block {
                                            18064673131860544307 => {}
                                            _ => {
                                                if (unsafe { (*uri).port }) > 0 as i32 {
                                                    if len + 10 as i32 >= max {
                                                        temp = xmlSaveUriRealloc(ret, &mut max);
                                                        if temp.is_null() {
                                                            current_block = 18064673131860544307;
                                                        } else {
                                                            ret = temp;
                                                            current_block = 993425571616822999;
                                                        }
                                                    } else {
                                                        current_block = 993425571616822999;
                                                    }
                                                    match current_block {
                                                        18064673131860544307 => {}
                                                        _ => {
                                                            len += unsafe { snprintf(
                                                                &mut *ret.offset(len as isize)
                                                                    as *mut xmlChar
                                                                    as *mut i8,
                                                                (max - len) as u64,
                                                                b":%d\0" as *const u8 as *const i8,
                                                                (*uri).port,
                                                            ) };
                                                            current_block = 9775647934248138666;
                                                        }
                                                    }
                                                } else {
                                                    current_block = 9775647934248138666;
                                                }
                                            }
                                        }
                                    } else {
                                        current_block = 9775647934248138666;
                                    }
                                }
                            }
                        }
                    }
                } else if !(unsafe { (*uri).authority }).is_null() {
                    if len + 3 as i32 >= max {
                        temp = xmlSaveUriRealloc(ret, &mut max);
                        if temp.is_null() {
                            current_block = 18064673131860544307;
                        } else {
                            ret = temp;
                            current_block = 12705158477165241210;
                        }
                    } else {
                        current_block = 12705158477165241210;
                    }
                    match current_block {
                        18064673131860544307 => {}
                        _ => {
                            let fresh46 = len;
                            len = len + 1;
                            (unsafe { *ret.offset(fresh46 as isize) = '/' as i32 as xmlChar });
                            let fresh47 = len;
                            len = len + 1;
                            (unsafe { *ret.offset(fresh47 as isize) = '/' as i32 as xmlChar });
                            p = unsafe { (*uri).authority };
                            loop {
                                if !((unsafe { *p }) as i32 != 0 as i32) {
                                    current_block = 9775647934248138666;
                                    break;
                                }
                                if len + 3 as i32 >= max {
                                    temp = xmlSaveUriRealloc(ret, &mut max);
                                    if temp.is_null() {
                                        current_block = 18064673131860544307;
                                        break;
                                    }
                                    ret = temp;
                                }
                                if (unsafe { *p }) as i32 >= 'a' as i32 && (unsafe { *p }) as i32 <= 'z' as i32
                                    || (unsafe { *p }) as i32 >= 'A' as i32 && (unsafe { *p }) as i32 <= 'Z' as i32
                                    || (unsafe { *p }) as i32 >= '0' as i32 && (unsafe { *p }) as i32 <= '9' as i32
                                    || ((unsafe { *p }) as i32 == '-' as i32
                                        || (unsafe { *p }) as i32 == '_' as i32
                                        || (unsafe { *p }) as i32 == '.' as i32
                                        || (unsafe { *p }) as i32 == '!' as i32
                                        || (unsafe { *p }) as i32 == '~' as i32
                                        || (unsafe { *p }) as i32 == '*' as i32
                                        || (unsafe { *p }) as i32 == '\'' as i32
                                        || (unsafe { *p }) as i32 == '(' as i32
                                        || (unsafe { *p }) as i32 == ')' as i32)
                                    || (unsafe { *p }) as i32 == '$' as i32
                                    || (unsafe { *p }) as i32 == ',' as i32
                                    || (unsafe { *p }) as i32 == ';' as i32
                                    || (unsafe { *p }) as i32 == ':' as i32
                                    || (unsafe { *p }) as i32 == '@' as i32
                                    || (unsafe { *p }) as i32 == '&' as i32
                                    || (unsafe { *p }) as i32 == '=' as i32
                                    || (unsafe { *p }) as i32 == '+' as i32
                                {
                                    let fresh48 = p;
                                    p = unsafe { p.offset(1) };
                                    let fresh49 = len;
                                    len = len + 1;
                                    (unsafe { *ret.offset(fresh49 as isize) = *fresh48 as xmlChar });
                                } else {
                                    let fresh50 = p;
                                    p = unsafe { p.offset(1) };
                                    let mut val_1: i32 = (unsafe { *(fresh50 as *mut u8) }) as i32;
                                    let mut hi_1: i32 = val_1 / 0x10 as i32;
                                    let mut lo_1: i32 = val_1 % 0x10 as i32;
                                    let fresh51 = len;
                                    len = len + 1;
                                    (unsafe { *ret.offset(fresh51 as isize) = '%' as i32 as xmlChar });
                                    let fresh52 = len;
                                    len = len + 1;
                                    (unsafe { *ret.offset(fresh52 as isize) = (hi_1
                                        + (if hi_1 > 9 as i32 {
                                            'A' as i32 - 10 as i32
                                        } else {
                                            '0' as i32
                                        }))
                                        as xmlChar });
                                    let fresh53 = len;
                                    len = len + 1;
                                    (unsafe { *ret.offset(fresh53 as isize) = (lo_1
                                        + (if lo_1 > 9 as i32 {
                                            'A' as i32 - 10 as i32
                                        } else {
                                            '0' as i32
                                        }))
                                        as xmlChar });
                                }
                            }
                        }
                    }
                } else if !(unsafe { (*uri).scheme }).is_null() {
                    if len + 3 as i32 >= max {
                        temp = xmlSaveUriRealloc(ret, &mut max);
                        if temp.is_null() {
                            current_block = 18064673131860544307;
                        } else {
                            ret = temp;
                            current_block = 9775647934248138666;
                        }
                    } else {
                        current_block = 9775647934248138666;
                    }
                } else {
                    current_block = 9775647934248138666;
                }
                match current_block {
                    18064673131860544307 => {}
                    _ => {
                        if !(unsafe { (*uri).path }).is_null() {
                            p = unsafe { (*uri).path };
                            if !(unsafe { (*uri).scheme }).is_null()
                                && (unsafe { *p.offset(0 as i32 as isize) }) as i32 == '/' as i32
                                && ((unsafe { *p.offset(1 as i32 as isize) }) as i32 >= 'a' as i32
                                    && (unsafe { *p.offset(1 as i32 as isize) }) as i32 <= 'z' as i32
                                    || (unsafe { *p.offset(1 as i32 as isize) }) as i32 >= 'A' as i32
                                        && (unsafe { *p.offset(1 as i32 as isize) }) as i32 <= 'Z' as i32)
                                && (unsafe { *p.offset(2 as i32 as isize) }) as i32 == ':' as i32
                                && (unsafe { xmlStrEqual(
                                    (*uri).scheme as *mut xmlChar,
                                    b"file\0" as *const u8 as *const i8 as *mut xmlChar,
                                ) }) != 0
                            {
                                if len + 3 as i32 >= max {
                                    temp = xmlSaveUriRealloc(ret, &mut max);
                                    if temp.is_null() {
                                        current_block = 18064673131860544307;
                                    } else {
                                        ret = temp;
                                        current_block = 5248622017361056354;
                                    }
                                } else {
                                    current_block = 5248622017361056354;
                                }
                                match current_block {
                                    18064673131860544307 => {}
                                    _ => {
                                        let fresh54 = p;
                                        p = unsafe { p.offset(1) };
                                        let fresh55 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh55 as isize) = *fresh54 as xmlChar });
                                        let fresh56 = p;
                                        p = unsafe { p.offset(1) };
                                        let fresh57 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh57 as isize) = *fresh56 as xmlChar });
                                        let fresh58 = p;
                                        p = unsafe { p.offset(1) };
                                        let fresh59 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh59 as isize) = *fresh58 as xmlChar });
                                        current_block = 13014351284863956202;
                                    }
                                }
                            } else {
                                current_block = 13014351284863956202;
                            }
                            match current_block {
                                18064673131860544307 => {}
                                _ => loop {
                                    if !((unsafe { *p }) as i32 != 0 as i32) {
                                        current_block = 7923086311623215889;
                                        break;
                                    }
                                    if len + 3 as i32 >= max {
                                        temp = xmlSaveUriRealloc(ret, &mut max);
                                        if temp.is_null() {
                                            current_block = 18064673131860544307;
                                            break;
                                        }
                                        ret = temp;
                                    }
                                    if (unsafe { *p }) as i32 >= 'a' as i32 && (unsafe { *p }) as i32 <= 'z' as i32
                                        || (unsafe { *p }) as i32 >= 'A' as i32 && (unsafe { *p }) as i32 <= 'Z' as i32
                                        || (unsafe { *p }) as i32 >= '0' as i32 && (unsafe { *p }) as i32 <= '9' as i32
                                        || ((unsafe { *p }) as i32 == '-' as i32
                                            || (unsafe { *p }) as i32 == '_' as i32
                                            || (unsafe { *p }) as i32 == '.' as i32
                                            || (unsafe { *p }) as i32 == '!' as i32
                                            || (unsafe { *p }) as i32 == '~' as i32
                                            || (unsafe { *p }) as i32 == '*' as i32
                                            || (unsafe { *p }) as i32 == '\'' as i32
                                            || (unsafe { *p }) as i32 == '(' as i32
                                            || (unsafe { *p }) as i32 == ')' as i32)
                                        || (unsafe { *p }) as i32 == '/' as i32
                                        || (unsafe { *p }) as i32 == ';' as i32
                                        || (unsafe { *p }) as i32 == '@' as i32
                                        || (unsafe { *p }) as i32 == '&' as i32
                                        || (unsafe { *p }) as i32 == '=' as i32
                                        || (unsafe { *p }) as i32 == '+' as i32
                                        || (unsafe { *p }) as i32 == '$' as i32
                                        || (unsafe { *p }) as i32 == ',' as i32
                                    {
                                        let fresh60 = p;
                                        p = unsafe { p.offset(1) };
                                        let fresh61 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh61 as isize) = *fresh60 as xmlChar });
                                    } else {
                                        let fresh62 = p;
                                        p = unsafe { p.offset(1) };
                                        let mut val_2: i32 = (unsafe { *(fresh62 as *mut u8) }) as i32;
                                        let mut hi_2: i32 = val_2 / 0x10 as i32;
                                        let mut lo_2: i32 = val_2 % 0x10 as i32;
                                        let fresh63 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh63 as isize) = '%' as i32 as xmlChar });
                                        let fresh64 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh64 as isize) = (hi_2
                                            + (if hi_2 > 9 as i32 {
                                                'A' as i32 - 10 as i32
                                            } else {
                                                '0' as i32
                                            }))
                                            as xmlChar });
                                        let fresh65 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh65 as isize) = (lo_2
                                            + (if lo_2 > 9 as i32 {
                                                'A' as i32 - 10 as i32
                                            } else {
                                                '0' as i32
                                            }))
                                            as xmlChar });
                                    }
                                },
                            }
                        } else {
                            current_block = 7923086311623215889;
                        }
                        match current_block {
                            18064673131860544307 => {}
                            _ => {
                                if !(unsafe { (*uri).query_raw }).is_null() {
                                    if len + 1 as i32 >= max {
                                        temp = xmlSaveUriRealloc(ret, &mut max);
                                        if temp.is_null() {
                                            current_block = 18064673131860544307;
                                        } else {
                                            ret = temp;
                                            current_block = 92352228884877657;
                                        }
                                    } else {
                                        current_block = 92352228884877657;
                                    }
                                    match current_block {
                                        18064673131860544307 => {}
                                        _ => {
                                            let fresh66 = len;
                                            len = len + 1;
                                            (unsafe { *ret.offset(fresh66 as isize) = '?' as i32 as xmlChar });
                                            p = unsafe { (*uri).query_raw };
                                            loop {
                                                if !((unsafe { *p }) as i32 != 0 as i32) {
                                                    current_block = 13161952823003036500;
                                                    break;
                                                }
                                                if len + 1 as i32 >= max {
                                                    temp = xmlSaveUriRealloc(ret, &mut max);
                                                    if temp.is_null() {
                                                        current_block = 18064673131860544307;
                                                        break;
                                                    }
                                                    ret = temp;
                                                }
                                                let fresh67 = p;
                                                p = unsafe { p.offset(1) };
                                                let fresh68 = len;
                                                len = len + 1;
                                                (unsafe { *ret.offset(fresh68 as isize) = *fresh67 as xmlChar });
                                            }
                                        }
                                    }
                                } else if !(unsafe { (*uri).query }).is_null() {
                                    if len + 3 as i32 >= max {
                                        temp = xmlSaveUriRealloc(ret, &mut max);
                                        if temp.is_null() {
                                            current_block = 18064673131860544307;
                                        } else {
                                            ret = temp;
                                            current_block = 2838755337219234678;
                                        }
                                    } else {
                                        current_block = 2838755337219234678;
                                    }
                                    match current_block {
                                        18064673131860544307 => {}
                                        _ => {
                                            let fresh69 = len;
                                            len = len + 1;
                                            (unsafe { *ret.offset(fresh69 as isize) = '?' as i32 as xmlChar });
                                            p = unsafe { (*uri).query };
                                            loop {
                                                if !((unsafe { *p }) as i32 != 0 as i32) {
                                                    current_block = 13161952823003036500;
                                                    break;
                                                }
                                                if len + 3 as i32 >= max {
                                                    temp = xmlSaveUriRealloc(ret, &mut max);
                                                    if temp.is_null() {
                                                        current_block = 18064673131860544307;
                                                        break;
                                                    }
                                                    ret = temp;
                                                }
                                                if (unsafe { *p }) as i32 >= 'a' as i32
                                                    && (unsafe { *p }) as i32 <= 'z' as i32
                                                    || (unsafe { *p }) as i32 >= 'A' as i32
                                                        && (unsafe { *p }) as i32 <= 'Z' as i32
                                                    || (unsafe { *p }) as i32 >= '0' as i32
                                                        && (unsafe { *p }) as i32 <= '9' as i32
                                                    || ((unsafe { *p }) as i32 == '-' as i32
                                                        || (unsafe { *p }) as i32 == '_' as i32
                                                        || (unsafe { *p }) as i32 == '.' as i32
                                                        || (unsafe { *p }) as i32 == '!' as i32
                                                        || (unsafe { *p }) as i32 == '~' as i32
                                                        || (unsafe { *p }) as i32 == '*' as i32
                                                        || (unsafe { *p }) as i32 == '\'' as i32
                                                        || (unsafe { *p }) as i32 == '(' as i32
                                                        || (unsafe { *p }) as i32 == ')' as i32)
                                                    || ((unsafe { *p }) as i32 == ';' as i32
                                                        || (unsafe { *p }) as i32 == '/' as i32
                                                        || (unsafe { *p }) as i32 == '?' as i32
                                                        || (unsafe { *p }) as i32 == ':' as i32
                                                        || (unsafe { *p }) as i32 == '@' as i32
                                                        || (unsafe { *p }) as i32 == '&' as i32
                                                        || (unsafe { *p }) as i32 == '=' as i32
                                                        || (unsafe { *p }) as i32 == '+' as i32
                                                        || (unsafe { *p }) as i32 == '$' as i32
                                                        || (unsafe { *p }) as i32 == ',' as i32
                                                        || (unsafe { *p }) as i32 == '[' as i32
                                                        || (unsafe { *p }) as i32 == ']' as i32)
                                                {
                                                    let fresh70 = p;
                                                    p = unsafe { p.offset(1) };
                                                    let fresh71 = len;
                                                    len = len + 1;
                                                    (unsafe { *ret.offset(fresh71 as isize) =
                                                        *fresh70 as xmlChar });
                                                } else {
                                                    let fresh72 = p;
                                                    p = unsafe { p.offset(1) };
                                                    let mut val_3: i32 =
                                                        (unsafe { *(fresh72 as *mut u8) }) as i32;
                                                    let mut hi_3: i32 = val_3 / 0x10 as i32;
                                                    let mut lo_3: i32 = val_3 % 0x10 as i32;
                                                    let fresh73 = len;
                                                    len = len + 1;
                                                    (unsafe { *ret.offset(fresh73 as isize) =
                                                        '%' as i32 as xmlChar });
                                                    let fresh74 = len;
                                                    len = len + 1;
                                                    (unsafe { *ret.offset(fresh74 as isize) = (hi_3
                                                        + (if hi_3 > 9 as i32 {
                                                            'A' as i32 - 10 as i32
                                                        } else {
                                                            '0' as i32
                                                        }))
                                                        as xmlChar });
                                                    let fresh75 = len;
                                                    len = len + 1;
                                                    (unsafe { *ret.offset(fresh75 as isize) = (lo_3
                                                        + (if lo_3 > 9 as i32 {
                                                            'A' as i32 - 10 as i32
                                                        } else {
                                                            '0' as i32
                                                        }))
                                                        as xmlChar });
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    current_block = 13161952823003036500;
                                }
                            }
                        }
                    }
                }
            }
            match current_block {
                18064673131860544307 => {}
                _ => {
                    if !(unsafe { (*uri).fragment }).is_null() {
                        if len + 3 as i32 >= max {
                            temp = xmlSaveUriRealloc(ret, &mut max);
                            if temp.is_null() {
                                current_block = 18064673131860544307;
                            } else {
                                ret = temp;
                                current_block = 654039154479240366;
                            }
                        } else {
                            current_block = 654039154479240366;
                        }
                        match current_block {
                            18064673131860544307 => {}
                            _ => {
                                let fresh76 = len;
                                len = len + 1;
                                (unsafe { *ret.offset(fresh76 as isize) = '#' as i32 as xmlChar });
                                p = unsafe { (*uri).fragment };
                                loop {
                                    if !((unsafe { *p }) as i32 != 0 as i32) {
                                        current_block = 7256998052328658819;
                                        break;
                                    }
                                    if len + 3 as i32 >= max {
                                        temp = xmlSaveUriRealloc(ret, &mut max);
                                        if temp.is_null() {
                                            current_block = 18064673131860544307;
                                            break;
                                        }
                                        ret = temp;
                                    }
                                    if (unsafe { *p }) as i32 >= 'a' as i32 && (unsafe { *p }) as i32 <= 'z' as i32
                                        || (unsafe { *p }) as i32 >= 'A' as i32 && (unsafe { *p }) as i32 <= 'Z' as i32
                                        || (unsafe { *p }) as i32 >= '0' as i32 && (unsafe { *p }) as i32 <= '9' as i32
                                        || ((unsafe { *p }) as i32 == '-' as i32
                                            || (unsafe { *p }) as i32 == '_' as i32
                                            || (unsafe { *p }) as i32 == '.' as i32
                                            || (unsafe { *p }) as i32 == '!' as i32
                                            || (unsafe { *p }) as i32 == '~' as i32
                                            || (unsafe { *p }) as i32 == '*' as i32
                                            || (unsafe { *p }) as i32 == '\'' as i32
                                            || (unsafe { *p }) as i32 == '(' as i32
                                            || (unsafe { *p }) as i32 == ')' as i32)
                                        || ((unsafe { *p }) as i32 == ';' as i32
                                            || (unsafe { *p }) as i32 == '/' as i32
                                            || (unsafe { *p }) as i32 == '?' as i32
                                            || (unsafe { *p }) as i32 == ':' as i32
                                            || (unsafe { *p }) as i32 == '@' as i32
                                            || (unsafe { *p }) as i32 == '&' as i32
                                            || (unsafe { *p }) as i32 == '=' as i32
                                            || (unsafe { *p }) as i32 == '+' as i32
                                            || (unsafe { *p }) as i32 == '$' as i32
                                            || (unsafe { *p }) as i32 == ',' as i32
                                            || (unsafe { *p }) as i32 == '[' as i32
                                            || (unsafe { *p }) as i32 == ']' as i32)
                                    {
                                        let fresh77 = p;
                                        p = unsafe { p.offset(1) };
                                        let fresh78 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh78 as isize) = *fresh77 as xmlChar });
                                    } else {
                                        let fresh79 = p;
                                        p = unsafe { p.offset(1) };
                                        let mut val_4: i32 = (unsafe { *(fresh79 as *mut u8) }) as i32;
                                        let mut hi_4: i32 = val_4 / 0x10 as i32;
                                        let mut lo_4: i32 = val_4 % 0x10 as i32;
                                        let fresh80 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh80 as isize) = '%' as i32 as xmlChar });
                                        let fresh81 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh81 as isize) = (hi_4
                                            + (if hi_4 > 9 as i32 {
                                                'A' as i32 - 10 as i32
                                            } else {
                                                '0' as i32
                                            }))
                                            as xmlChar });
                                        let fresh82 = len;
                                        len = len + 1;
                                        (unsafe { *ret.offset(fresh82 as isize) = (lo_4
                                            + (if lo_4 > 9 as i32 {
                                                'A' as i32 - 10 as i32
                                            } else {
                                                '0' as i32
                                            }))
                                            as xmlChar });
                                    }
                                }
                            }
                        }
                    } else {
                        current_block = 7256998052328658819;
                    }
                    match current_block {
                        18064673131860544307 => {}
                        _ => {
                            if len >= max {
                                temp = xmlSaveUriRealloc(ret, &mut max);
                                if temp.is_null() {
                                    current_block = 18064673131860544307;
                                } else {
                                    ret = temp;
                                    current_block = 16813369756331276724;
                                }
                            } else {
                                current_block = 16813369756331276724;
                            }
                            match current_block {
                                18064673131860544307 => {}
                                _ => {
                                    (unsafe { *ret.offset(len as isize) = 0 as i32 as xmlChar });
                                    return ret;
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlPrintURI(mut stream: *mut FILE, mut uri: xmlURIPtr) {
    let mut out: *mut xmlChar = 0 as *mut xmlChar;
    out = xmlSaveUri(uri);
    if !out.is_null() {
        (unsafe { fprintf(stream, b"%s\0" as *const u8 as *const i8, out as *mut i8) });
        (unsafe { xmlFree.expect("non-null function pointer")(out as *mut libc::c_void) });
    }
}
extern "C" fn xmlCleanURI(mut uri: xmlURIPtr) {
    if uri.is_null() {
        return;
    }
    if !(unsafe { (*uri).scheme }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).scheme as *mut libc::c_void) });
    }
    let fresh83 = unsafe { &mut ((*uri).scheme) };
    *fresh83 = 0 as *mut i8;
    if !(unsafe { (*uri).server }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).server as *mut libc::c_void) });
    }
    let fresh84 = unsafe { &mut ((*uri).server) };
    *fresh84 = 0 as *mut i8;
    if !(unsafe { (*uri).user }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).user as *mut libc::c_void) });
    }
    let fresh85 = unsafe { &mut ((*uri).user) };
    *fresh85 = 0 as *mut i8;
    if !(unsafe { (*uri).path }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).path as *mut libc::c_void) });
    }
    let fresh86 = unsafe { &mut ((*uri).path) };
    *fresh86 = 0 as *mut i8;
    if !(unsafe { (*uri).fragment }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).fragment as *mut libc::c_void) });
    }
    let fresh87 = unsafe { &mut ((*uri).fragment) };
    *fresh87 = 0 as *mut i8;
    if !(unsafe { (*uri).opaque }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).opaque as *mut libc::c_void) });
    }
    let fresh88 = unsafe { &mut ((*uri).opaque) };
    *fresh88 = 0 as *mut i8;
    if !(unsafe { (*uri).authority }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).authority as *mut libc::c_void) });
    }
    let fresh89 = unsafe { &mut ((*uri).authority) };
    *fresh89 = 0 as *mut i8;
    if !(unsafe { (*uri).query }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).query as *mut libc::c_void) });
    }
    let fresh90 = unsafe { &mut ((*uri).query) };
    *fresh90 = 0 as *mut i8;
    if !(unsafe { (*uri).query_raw }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).query_raw as *mut libc::c_void) });
    }
    let fresh91 = unsafe { &mut ((*uri).query_raw) };
    *fresh91 = 0 as *mut i8;
}
#[no_mangle]
pub extern "C" fn xmlFreeURI(mut uri: xmlURIPtr) {
    if uri.is_null() {
        return;
    }
    if !(unsafe { (*uri).scheme }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).scheme as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).server }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).server as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).user }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).user as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).path }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).path as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).fragment }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).fragment as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).opaque }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).opaque as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).authority }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).authority as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).query }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).query as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).query_raw }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*uri).query_raw as *mut libc::c_void) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(uri as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlNormalizeURIPath(mut path: *mut i8) -> i32 {
    let mut cur: *mut i8 = 0 as *mut i8;
    let mut out: *mut i8 = 0 as *mut i8;
    if path.is_null() {
        return -(1 as i32);
    }
    cur = path;
    while (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '/' as i32 {
        cur = unsafe { cur.offset(1) };
    }
    if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '\u{0}' as i32 {
        return 0 as i32;
    }
    out = cur;
    's_39: while (unsafe { *cur.offset(0 as i32 as isize) }) as i32 != '\u{0}' as i32 {
        if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '.' as i32
            && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '/' as i32
        {
            cur = unsafe { cur.offset(2 as i32 as isize) };
            while (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '/' as i32 {
                cur = unsafe { cur.offset(1) };
            }
        } else {
            if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '.' as i32
                && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '\u{0}' as i32
            {
                break;
            }
            while (unsafe { *cur.offset(0 as i32 as isize) }) as i32 != '/' as i32 {
                if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '\u{0}' as i32 {
                    break 's_39;
                }
                let fresh92 = cur;
                cur = unsafe { cur.offset(1) };
                let fresh93 = out;
                out = unsafe { out.offset(1) };
                (unsafe { *fresh93.offset(0 as i32 as isize) = *fresh92.offset(0 as i32 as isize) });
            }
            while (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '/' as i32
                && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '/' as i32
            {
                cur = unsafe { cur.offset(1) };
            }
            let fresh94 = cur;
            cur = unsafe { cur.offset(1) };
            let fresh95 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh95.offset(0 as i32 as isize) = *fresh94.offset(0 as i32 as isize) });
        }
    }
    (unsafe { *out.offset(0 as i32 as isize) = '\u{0}' as i32 as i8 });
    cur = path;
    while (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '/' as i32 {
        cur = unsafe { cur.offset(1) };
    }
    if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '\u{0}' as i32 {
        return 0 as i32;
    }
    loop {
        let mut segp: *mut i8 = 0 as *mut i8;
        let mut tmp: *mut i8 = 0 as *mut i8;
        segp = cur;
        while (unsafe { *segp.offset(0 as i32 as isize) }) as i32 != '/' as i32
            && (unsafe { *segp.offset(0 as i32 as isize) }) as i32 != '\u{0}' as i32
        {
            segp = unsafe { segp.offset(1) };
        }
        if (unsafe { *segp.offset(0 as i32 as isize) }) as i32 == '\u{0}' as i32 {
            break;
        }
        segp = unsafe { segp.offset(1) };
        if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '.' as i32
            && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '.' as i32
            && segp == (unsafe { cur.offset(3 as i32 as isize) })
            || ((unsafe { *segp.offset(0 as i32 as isize) }) as i32 != '.' as i32
                || (unsafe { *segp.offset(1 as i32 as isize) }) as i32 != '.' as i32
                || (unsafe { *segp.offset(2 as i32 as isize) }) as i32 != '/' as i32
                    && (unsafe { *segp.offset(2 as i32 as isize) }) as i32 != '\u{0}' as i32)
        {
            cur = segp;
        } else if (unsafe { *segp.offset(2 as i32 as isize) }) as i32 == '\u{0}' as i32 {
            (unsafe { *cur.offset(0 as i32 as isize) = '\u{0}' as i32 as i8 });
            break;
        } else {
            tmp = cur;
            segp = unsafe { segp.offset(3 as i32 as isize) };
            loop {
                let fresh96 = segp;
                segp = unsafe { segp.offset(1) };
                let fresh97 = tmp;
                tmp = unsafe { tmp.offset(1) };
                (unsafe { *fresh97 = *fresh96 });
                if !((unsafe { *fresh97 }) as i32 != 0 as i32) {
                    break;
                }
            }
            segp = cur;
            while segp > path && {
                segp = unsafe { segp.offset(-1) };
                (unsafe { *segp.offset(0 as i32 as isize) }) as i32 == '/' as i32
            } {}
            if segp == path {
                continue;
            }
            cur = segp;
            while cur > path && (unsafe { *cur.offset(-(1 as i32) as isize) }) as i32 != '/' as i32 {
                cur = unsafe { cur.offset(-1) };
            }
        }
    }
    (unsafe { *out.offset(0 as i32 as isize) = '\u{0}' as i32 as i8 });
    if (unsafe { *path.offset(0 as i32 as isize) }) as i32 == '/' as i32 {
        cur = path;
        while (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '/' as i32
            && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '.' as i32
            && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 == '.' as i32
            && ((unsafe { *cur.offset(3 as i32 as isize) }) as i32 == '/' as i32
                || (unsafe { *cur.offset(3 as i32 as isize) }) as i32 == '\u{0}' as i32)
        {
            cur = unsafe { cur.offset(3 as i32 as isize) };
        }
        if cur != path {
            out = path;
            while (unsafe { *cur.offset(0 as i32 as isize) }) as i32 != '\u{0}' as i32 {
                let fresh98 = cur;
                cur = unsafe { cur.offset(1) };
                let fresh99 = out;
                out = unsafe { out.offset(1) };
                (unsafe { *fresh99.offset(0 as i32 as isize) = *fresh98.offset(0 as i32 as isize) });
            }
            (unsafe { *out.offset(0 as i32 as isize) = 0 as i32 as i8 });
        }
    }
    return 0 as i32;
}
extern "C" fn is_hex(mut c: i8) -> i32 {
    if c as i32 >= '0' as i32 && c as i32 <= '9' as i32
        || c as i32 >= 'a' as i32 && c as i32 <= 'f' as i32
        || c as i32 >= 'A' as i32 && c as i32 <= 'F' as i32
    {
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlURIUnescapeString(
    mut str: *const i8,
    mut len: i32,
    mut target: *mut i8,
) -> *mut i8 {
    let mut ret: *mut i8 = 0 as *mut i8;
    let mut out: *mut i8 = 0 as *mut i8;
    let mut in_0: *const i8 = 0 as *const i8;
    if str.is_null() {
        return 0 as *mut i8;
    }
    if len <= 0 as i32 {
        len = (unsafe { strlen(str) }) as i32;
    }
    if len < 0 as i32 {
        return 0 as *mut i8;
    }
    if target.is_null() {
        ret = (unsafe { xmlMallocAtomic.expect("non-null function pointer")((len + 1 as i32) as size_t) })
            as *mut i8;
        if ret.is_null() {
            xmlURIErrMemory(b"unescaping URI value\n\0" as *const u8 as *const i8);
            return 0 as *mut i8;
        }
    } else {
        ret = target;
    }
    in_0 = str;
    out = ret;
    while len > 0 as i32 {
        if len > 2 as i32
            && (unsafe { *in_0 }) as i32 == '%' as i32
            && is_hex(unsafe { *in_0.offset(1 as i32 as isize) }) != 0
            && is_hex(unsafe { *in_0.offset(2 as i32 as isize) }) != 0
        {
            let mut c: i32 = 0 as i32;
            in_0 = unsafe { in_0.offset(1) };
            if (unsafe { *in_0 }) as i32 >= '0' as i32 && (unsafe { *in_0 }) as i32 <= '9' as i32 {
                c = (unsafe { *in_0 }) as i32 - '0' as i32;
            } else if (unsafe { *in_0 }) as i32 >= 'a' as i32 && (unsafe { *in_0 }) as i32 <= 'f' as i32 {
                c = (unsafe { *in_0 }) as i32 - 'a' as i32 + 10 as i32;
            } else if (unsafe { *in_0 }) as i32 >= 'A' as i32 && (unsafe { *in_0 }) as i32 <= 'F' as i32 {
                c = (unsafe { *in_0 }) as i32 - 'A' as i32 + 10 as i32;
            }
            in_0 = unsafe { in_0.offset(1) };
            if (unsafe { *in_0 }) as i32 >= '0' as i32 && (unsafe { *in_0 }) as i32 <= '9' as i32 {
                c = c * 16 as i32 + ((unsafe { *in_0 }) as i32 - '0' as i32);
            } else if (unsafe { *in_0 }) as i32 >= 'a' as i32 && (unsafe { *in_0 }) as i32 <= 'f' as i32 {
                c = c * 16 as i32 + ((unsafe { *in_0 }) as i32 - 'a' as i32) + 10 as i32;
            } else if (unsafe { *in_0 }) as i32 >= 'A' as i32 && (unsafe { *in_0 }) as i32 <= 'F' as i32 {
                c = c * 16 as i32 + ((unsafe { *in_0 }) as i32 - 'A' as i32) + 10 as i32;
            }
            in_0 = unsafe { in_0.offset(1) };
            len -= 3 as i32;
            let fresh100 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh100 = c as i8 });
        } else {
            let fresh101 = in_0;
            in_0 = unsafe { in_0.offset(1) };
            let fresh102 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh102 = *fresh101 });
            len -= 1;
        }
    }
    (unsafe { *out = 0 as i32 as i8 });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlURIEscapeStr(
    mut str: *const xmlChar,
    mut list: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut ch: xmlChar = 0;
    let mut temp: *mut xmlChar = 0 as *mut xmlChar;
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut len: i32 = 0;
    let mut out: i32 = 0;
    if str.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { *str.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
        return unsafe { xmlStrdup(str) };
    }
    len = unsafe { xmlStrlen(str) };
    if !(len > 0 as i32) {
        return 0 as *mut xmlChar;
    }
    len += 20 as i32;
    ret = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(len as size_t) }) as *mut xmlChar;
    if ret.is_null() {
        xmlURIErrMemory(b"escaping URI value\n\0" as *const u8 as *const i8);
        return 0 as *mut xmlChar;
    }
    in_0 = str;
    out = 0 as i32;
    while (unsafe { *in_0 }) as i32 != 0 as i32 {
        if len - out <= 3 as i32 {
            temp = xmlSaveUriRealloc(ret, &mut len);
            if temp.is_null() {
                xmlURIErrMemory(b"escaping URI value\n\0" as *const u8 as *const i8);
                (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
                return 0 as *mut xmlChar;
            }
            ret = temp;
        }
        ch = unsafe { *in_0 };
        if ch as i32 != '@' as i32
            && !(ch as i32 >= 'a' as i32 && ch as i32 <= 'z' as i32
                || ch as i32 >= 'A' as i32 && ch as i32 <= 'Z' as i32
                || ch as i32 >= '0' as i32 && ch as i32 <= '9' as i32
                || (ch as i32 == '-' as i32
                    || ch as i32 == '_' as i32
                    || ch as i32 == '.' as i32
                    || ch as i32 == '!' as i32
                    || ch as i32 == '~' as i32
                    || ch as i32 == '*' as i32
                    || ch as i32 == '\'' as i32
                    || ch as i32 == '(' as i32
                    || ch as i32 == ')' as i32))
            && (unsafe { xmlStrchr(list, ch) }).is_null()
        {
            let mut val: u8 = 0;
            let fresh103 = out;
            out = out + 1;
            (unsafe { *ret.offset(fresh103 as isize) = '%' as i32 as xmlChar });
            val = (ch as i32 >> 4 as i32) as u8;
            if val as i32 <= 9 as i32 {
                let fresh104 = out;
                out = out + 1;
                (unsafe { *ret.offset(fresh104 as isize) = ('0' as i32 + val as i32) as xmlChar });
            } else {
                let fresh105 = out;
                out = out + 1;
                (unsafe { *ret.offset(fresh105 as isize) = ('A' as i32 + val as i32 - 0xa as i32) as xmlChar });
            }
            val = (ch as i32 & 0xf as i32) as u8;
            if val as i32 <= 9 as i32 {
                let fresh106 = out;
                out = out + 1;
                (unsafe { *ret.offset(fresh106 as isize) = ('0' as i32 + val as i32) as xmlChar });
            } else {
                let fresh107 = out;
                out = out + 1;
                (unsafe { *ret.offset(fresh107 as isize) = ('A' as i32 + val as i32 - 0xa as i32) as xmlChar });
            }
            in_0 = unsafe { in_0.offset(1) };
        } else {
            let fresh108 = in_0;
            in_0 = unsafe { in_0.offset(1) };
            let fresh109 = out;
            out = out + 1;
            (unsafe { *ret.offset(fresh109 as isize) = *fresh108 });
        }
    }
    (unsafe { *ret.offset(out as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlURIEscape(mut str: *const xmlChar) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut segment: *mut xmlChar = 0 as *mut xmlChar;
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut ret2: i32 = 0;
    if str.is_null() {
        return 0 as *mut xmlChar;
    }
    uri = xmlCreateURI();
    if !uri.is_null() {
        (unsafe { (*uri).cleanup = 1 as i32 });
        ret2 = xmlParseURIReference(uri, str as *const i8);
        if ret2 != 0 {
            xmlFreeURI(uri);
            return 0 as *mut xmlChar;
        }
    }
    if uri.is_null() {
        return 0 as *mut xmlChar;
    }
    ret = 0 as *mut xmlChar;
    if !(unsafe { (*uri).scheme }).is_null() {
        segment = xmlURIEscapeStr(
            (unsafe { (*uri).scheme }) as *mut xmlChar,
            b"+-.\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        if segment.is_null() {
            xmlURIErrMemory(b"escaping URI value\n\0" as *const u8 as *const i8);
            xmlFreeURI(uri);
            (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
            return 0 as *mut xmlChar;
        }
        ret = unsafe { xmlStrcat(ret, segment) };
        ret = unsafe { xmlStrcat(ret, b":\0" as *const u8 as *const i8 as *mut xmlChar) };
        (unsafe { xmlFree.expect("non-null function pointer")(segment as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).authority }).is_null() {
        segment = xmlURIEscapeStr(
            (unsafe { (*uri).authority }) as *mut xmlChar,
            b"/?;:@\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        if segment.is_null() {
            xmlURIErrMemory(b"escaping URI value\n\0" as *const u8 as *const i8);
            xmlFreeURI(uri);
            (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
            return 0 as *mut xmlChar;
        }
        ret = unsafe { xmlStrcat(ret, b"//\0" as *const u8 as *const i8 as *mut xmlChar) };
        ret = unsafe { xmlStrcat(ret, segment) };
        (unsafe { xmlFree.expect("non-null function pointer")(segment as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).user }).is_null() {
        segment = xmlURIEscapeStr(
            (unsafe { (*uri).user }) as *mut xmlChar,
            b";:&=+$,\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        if segment.is_null() {
            xmlURIErrMemory(b"escaping URI value\n\0" as *const u8 as *const i8);
            xmlFreeURI(uri);
            (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
            return 0 as *mut xmlChar;
        }
        ret = unsafe { xmlStrcat(ret, b"//\0" as *const u8 as *const i8 as *mut xmlChar) };
        ret = unsafe { xmlStrcat(ret, segment) };
        ret = unsafe { xmlStrcat(ret, b"@\0" as *const u8 as *const i8 as *mut xmlChar) };
        (unsafe { xmlFree.expect("non-null function pointer")(segment as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).server }).is_null() {
        segment = xmlURIEscapeStr(
            (unsafe { (*uri).server }) as *mut xmlChar,
            b"/?;:@\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        if segment.is_null() {
            xmlURIErrMemory(b"escaping URI value\n\0" as *const u8 as *const i8);
            xmlFreeURI(uri);
            (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
            return 0 as *mut xmlChar;
        }
        if (unsafe { (*uri).user }).is_null() {
            ret = unsafe { xmlStrcat(ret, b"//\0" as *const u8 as *const i8 as *mut xmlChar) };
        }
        ret = unsafe { xmlStrcat(ret, segment) };
        (unsafe { xmlFree.expect("non-null function pointer")(segment as *mut libc::c_void) });
    }
    if (unsafe { (*uri).port }) != 0 {
        let mut port: [xmlChar; 10] = [0; 10];
        (unsafe { snprintf(
            port.as_mut_ptr() as *mut i8,
            10 as i32 as u64,
            b"%d\0" as *const u8 as *const i8,
            (*uri).port,
        ) });
        ret = unsafe { xmlStrcat(ret, b":\0" as *const u8 as *const i8 as *mut xmlChar) };
        ret = unsafe { xmlStrcat(ret, port.as_mut_ptr()) };
    }
    if !(unsafe { (*uri).path }).is_null() {
        segment = xmlURIEscapeStr(
            (unsafe { (*uri).path }) as *mut xmlChar,
            b":@&=+$,/?;\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        if segment.is_null() {
            xmlURIErrMemory(b"escaping URI value\n\0" as *const u8 as *const i8);
            xmlFreeURI(uri);
            (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
            return 0 as *mut xmlChar;
        }
        ret = unsafe { xmlStrcat(ret, segment) };
        (unsafe { xmlFree.expect("non-null function pointer")(segment as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).query_raw }).is_null() {
        ret = unsafe { xmlStrcat(ret, b"?\0" as *const u8 as *const i8 as *mut xmlChar) };
        ret = unsafe { xmlStrcat(ret, (*uri).query_raw as *mut xmlChar) };
    } else if !(unsafe { (*uri).query }).is_null() {
        segment = xmlURIEscapeStr(
            (unsafe { (*uri).query }) as *mut xmlChar,
            b";/?:@&=+,$\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        if segment.is_null() {
            xmlURIErrMemory(b"escaping URI value\n\0" as *const u8 as *const i8);
            xmlFreeURI(uri);
            (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
            return 0 as *mut xmlChar;
        }
        ret = unsafe { xmlStrcat(ret, b"?\0" as *const u8 as *const i8 as *mut xmlChar) };
        ret = unsafe { xmlStrcat(ret, segment) };
        (unsafe { xmlFree.expect("non-null function pointer")(segment as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).opaque }).is_null() {
        segment = xmlURIEscapeStr(
            (unsafe { (*uri).opaque }) as *mut xmlChar,
            b"\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        if segment.is_null() {
            xmlURIErrMemory(b"escaping URI value\n\0" as *const u8 as *const i8);
            xmlFreeURI(uri);
            (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
            return 0 as *mut xmlChar;
        }
        ret = unsafe { xmlStrcat(ret, segment) };
        (unsafe { xmlFree.expect("non-null function pointer")(segment as *mut libc::c_void) });
    }
    if !(unsafe { (*uri).fragment }).is_null() {
        segment = xmlURIEscapeStr(
            (unsafe { (*uri).fragment }) as *mut xmlChar,
            b"#\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        if segment.is_null() {
            xmlURIErrMemory(b"escaping URI value\n\0" as *const u8 as *const i8);
            xmlFreeURI(uri);
            (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
            return 0 as *mut xmlChar;
        }
        ret = unsafe { xmlStrcat(ret, b"#\0" as *const u8 as *const i8 as *mut xmlChar) };
        ret = unsafe { xmlStrcat(ret, segment) };
        (unsafe { xmlFree.expect("non-null function pointer")(segment as *mut libc::c_void) });
    }
    xmlFreeURI(uri);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlBuildURI(mut URI: *const xmlChar, mut base: *const xmlChar) -> *mut xmlChar {
    let mut current_block: u64;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    let mut ret: i32 = 0;
    let mut len: i32 = 0;
    let mut indx: i32 = 0;
    let mut cur: i32 = 0;
    let mut out: i32 = 0;
    let mut ref_0: xmlURIPtr = 0 as xmlURIPtr;
    let mut bas: xmlURIPtr = 0 as xmlURIPtr;
    let mut res: xmlURIPtr = 0 as xmlURIPtr;
    if URI.is_null() {
        ret = -(1 as i32);
        current_block = 13109137661213826276;
    } else if (unsafe { *URI }) != 0 {
        ref_0 = xmlCreateURI();
        if ref_0.is_null() {
            current_block = 10227634464655804289;
        } else {
            ret = xmlParseURIReference(ref_0, URI as *const i8);
            current_block = 13109137661213826276;
        }
    } else {
        ret = 0 as i32;
        current_block = 13109137661213826276;
    }
    match current_block {
        13109137661213826276 => {
            if !(ret != 0 as i32) {
                if !ref_0.is_null() && !(unsafe { (*ref_0).scheme }).is_null() {
                    val = unsafe { xmlStrdup(URI) };
                } else {
                    if base.is_null() {
                        ret = -(1 as i32);
                        current_block = 7175849428784450219;
                    } else {
                        bas = xmlCreateURI();
                        if bas.is_null() {
                            current_block = 10227634464655804289;
                        } else {
                            ret = xmlParseURIReference(bas, base as *const i8);
                            current_block = 7175849428784450219;
                        }
                    }
                    match current_block {
                        10227634464655804289 => {}
                        _ => {
                            if ret != 0 as i32 {
                                if !ref_0.is_null() {
                                    val = xmlSaveUri(ref_0);
                                }
                            } else if ref_0.is_null() {
                                if !(unsafe { (*bas).fragment }).is_null() {
                                    (unsafe { xmlFree.expect("non-null function pointer")(
                                        (*bas).fragment as *mut libc::c_void,
                                    ) });
                                    let fresh110 = unsafe { &mut ((*bas).fragment) };
                                    *fresh110 = 0 as *mut i8;
                                }
                                val = xmlSaveUri(bas);
                            } else {
                                res = xmlCreateURI();
                                if !res.is_null() {
                                    if (unsafe { (*ref_0).scheme }).is_null()
                                        && (unsafe { (*ref_0).path }).is_null()
                                        && ((unsafe { (*ref_0).authority }).is_null()
                                            && (unsafe { (*ref_0).server }).is_null())
                                    {
                                        if !(unsafe { (*bas).scheme }).is_null() {
                                            let fresh111 = unsafe { &mut ((*res).scheme) };
                                            *fresh111 = unsafe { xmlMemStrdup
                                                .expect("non-null function pointer")(
                                                (*bas).scheme
                                            ) };
                                        }
                                        if !(unsafe { (*bas).authority }).is_null() {
                                            let fresh112 = unsafe { &mut ((*res).authority) };
                                            *fresh112 = unsafe { xmlMemStrdup
                                                .expect("non-null function pointer")(
                                                (*bas).authority,
                                            ) };
                                        } else if !(unsafe { (*bas).server }).is_null()
                                            || (unsafe { (*bas).port }) == -(1 as i32)
                                        {
                                            if !(unsafe { (*bas).server }).is_null() {
                                                let fresh113 = unsafe { &mut ((*res).server) };
                                                *fresh113 = unsafe { xmlMemStrdup
                                                    .expect("non-null function pointer")(
                                                    (*bas).server,
                                                ) };
                                            }
                                            if !(unsafe { (*bas).user }).is_null() {
                                                let fresh114 = unsafe { &mut ((*res).user) };
                                                *fresh114 = unsafe { xmlMemStrdup
                                                    .expect("non-null function pointer")(
                                                    (*bas).user,
                                                ) };
                                            }
                                            (unsafe { (*res).port = (*bas).port });
                                        }
                                        if !(unsafe { (*bas).path }).is_null() {
                                            let fresh115 = unsafe { &mut ((*res).path) };
                                            *fresh115 = unsafe { xmlMemStrdup
                                                .expect("non-null function pointer")(
                                                (*bas).path
                                            ) };
                                        }
                                        if !(unsafe { (*ref_0).query_raw }).is_null() {
                                            let fresh116 = unsafe { &mut ((*res).query_raw) };
                                            *fresh116 = unsafe { xmlMemStrdup
                                                .expect("non-null function pointer")(
                                                (*ref_0).query_raw,
                                            ) };
                                        } else if !(unsafe { (*ref_0).query }).is_null() {
                                            let fresh117 = unsafe { &mut ((*res).query) };
                                            *fresh117 = unsafe { xmlMemStrdup
                                                .expect("non-null function pointer")(
                                                (*ref_0).query,
                                            ) };
                                        } else if !(unsafe { (*bas).query_raw }).is_null() {
                                            let fresh118 = unsafe { &mut ((*res).query_raw) };
                                            *fresh118 = unsafe { xmlMemStrdup
                                                .expect("non-null function pointer")(
                                                (*bas).query_raw,
                                            ) };
                                        } else if !(unsafe { (*bas).query }).is_null() {
                                            let fresh119 = unsafe { &mut ((*res).query) };
                                            *fresh119 = unsafe { xmlMemStrdup
                                                .expect("non-null function pointer")(
                                                (*bas).query
                                            ) };
                                        }
                                        if !(unsafe { (*ref_0).fragment }).is_null() {
                                            let fresh120 = unsafe { &mut ((*res).fragment) };
                                            *fresh120 = unsafe { xmlMemStrdup
                                                .expect("non-null function pointer")(
                                                (*ref_0).fragment,
                                            ) };
                                        }
                                        current_block = 17921910600917564308;
                                    } else if !(unsafe { (*ref_0).scheme }).is_null() {
                                        val = xmlSaveUri(ref_0);
                                        current_block = 10227634464655804289;
                                    } else {
                                        if !(unsafe { (*bas).scheme }).is_null() {
                                            let fresh121 = unsafe { &mut ((*res).scheme) };
                                            *fresh121 = unsafe { xmlMemStrdup
                                                .expect("non-null function pointer")(
                                                (*bas).scheme
                                            ) };
                                        }
                                        if !(unsafe { (*ref_0).query_raw }).is_null() {
                                            let fresh122 = unsafe { &mut ((*res).query_raw) };
                                            *fresh122 = unsafe { xmlMemStrdup
                                                .expect("non-null function pointer")(
                                                (*ref_0).query_raw,
                                            ) };
                                        } else if !(unsafe { (*ref_0).query }).is_null() {
                                            let fresh123 = unsafe { &mut ((*res).query) };
                                            *fresh123 = unsafe { xmlMemStrdup
                                                .expect("non-null function pointer")(
                                                (*ref_0).query,
                                            ) };
                                        }
                                        if !(unsafe { (*ref_0).fragment }).is_null() {
                                            let fresh124 = unsafe { &mut ((*res).fragment) };
                                            *fresh124 = unsafe { xmlMemStrdup
                                                .expect("non-null function pointer")(
                                                (*ref_0).fragment,
                                            ) };
                                        }
                                        if !(unsafe { (*ref_0).authority }).is_null()
                                            || !(unsafe { (*ref_0).server }).is_null()
                                        {
                                            if !(unsafe { (*ref_0).authority }).is_null() {
                                                let fresh125 = unsafe { &mut ((*res).authority) };
                                                *fresh125 = unsafe { xmlMemStrdup
                                                    .expect("non-null function pointer")(
                                                    (*ref_0).authority,
                                                ) };
                                            } else {
                                                let fresh126 = unsafe { &mut ((*res).server) };
                                                *fresh126 = unsafe { xmlMemStrdup
                                                    .expect("non-null function pointer")(
                                                    (*ref_0).server,
                                                ) };
                                                if !(unsafe { (*ref_0).user }).is_null() {
                                                    let fresh127 = unsafe { &mut ((*res).user) };
                                                    *fresh127 = unsafe { xmlMemStrdup
                                                        .expect("non-null function pointer")(
                                                        (*ref_0).user,
                                                    ) };
                                                }
                                                (unsafe { (*res).port = (*ref_0).port });
                                            }
                                            if !(unsafe { (*ref_0).path }).is_null() {
                                                let fresh128 = unsafe { &mut ((*res).path) };
                                                *fresh128 = unsafe { xmlMemStrdup
                                                    .expect("non-null function pointer")(
                                                    (*ref_0).path,
                                                ) };
                                            }
                                            current_block = 17921910600917564308;
                                        } else {
                                            if !(unsafe { (*bas).authority }).is_null() {
                                                let fresh129 = unsafe { &mut ((*res).authority) };
                                                *fresh129 = unsafe { xmlMemStrdup
                                                    .expect("non-null function pointer")(
                                                    (*bas).authority,
                                                ) };
                                            } else if !(unsafe { (*bas).server }).is_null()
                                                || (unsafe { (*bas).port }) == -(1 as i32)
                                            {
                                                if !(unsafe { (*bas).server }).is_null() {
                                                    let fresh130 = unsafe { &mut ((*res).server) };
                                                    *fresh130 = unsafe { xmlMemStrdup
                                                        .expect("non-null function pointer")(
                                                        (*bas).server,
                                                    ) };
                                                }
                                                if !(unsafe { (*bas).user }).is_null() {
                                                    let fresh131 = unsafe { &mut ((*res).user) };
                                                    *fresh131 = unsafe { xmlMemStrdup
                                                        .expect("non-null function pointer")(
                                                        (*bas).user,
                                                    ) };
                                                }
                                                (unsafe { (*res).port = (*bas).port });
                                            }
                                            if !(unsafe { (*ref_0).path }).is_null()
                                                && (unsafe { *((*ref_0).path).offset(0 as i32 as isize) }) as i32
                                                    == '/' as i32
                                            {
                                                let fresh132 = unsafe { &mut ((*res).path) };
                                                *fresh132 = unsafe { xmlMemStrdup
                                                    .expect("non-null function pointer")(
                                                    (*ref_0).path,
                                                ) };
                                                current_block = 17921910600917564308;
                                            } else {
                                                len = 2 as i32;
                                                if !(unsafe { (*ref_0).path }).is_null() {
                                                    len = (len as u64)
                                                        .wrapping_add(unsafe { strlen((*ref_0).path) })
                                                        as i32
                                                        as i32;
                                                }
                                                if !(unsafe { (*bas).path }).is_null() {
                                                    len = (len as u64)
                                                        .wrapping_add(unsafe { strlen((*bas).path) })
                                                        as i32
                                                        as i32;
                                                }
                                                let fresh133 = unsafe { &mut ((*res).path) };
                                                *fresh133 = (unsafe { xmlMallocAtomic
                                                    .expect("non-null function pointer")(
                                                    len as size_t,
                                                ) })
                                                    as *mut i8;
                                                if (unsafe { (*res).path }).is_null() {
                                                    xmlURIErrMemory(
                                                        b"resolving URI against base\n\0"
                                                            as *const u8
                                                            as *const i8,
                                                    );
                                                    current_block = 10227634464655804289;
                                                } else {
                                                    (unsafe { *((*res).path).offset(0 as i32 as isize) =
                                                        0 as i32 as i8 });
                                                    cur = 0 as i32;
                                                    out = 0 as i32;
                                                    if !(unsafe { (*bas).path }).is_null() {
                                                        while (unsafe { *((*bas).path).offset(cur as isize) })
                                                            as i32
                                                            != 0 as i32
                                                        {
                                                            while (unsafe { *((*bas).path)
                                                                .offset(cur as isize) })
                                                                as i32
                                                                != 0 as i32
                                                                && (unsafe { *((*bas).path)
                                                                    .offset(cur as isize) })
                                                                    as i32
                                                                    != '/' as i32
                                                            {
                                                                cur += 1;
                                                            }
                                                            if (unsafe { *((*bas).path).offset(cur as isize) })
                                                                as i32
                                                                == 0 as i32
                                                            {
                                                                break;
                                                            }
                                                            cur += 1;
                                                            while out < cur {
                                                                (unsafe { *((*res).path)
                                                                    .offset(out as isize) =
                                                                    *((*bas).path)
                                                                        .offset(out as isize) });
                                                                out += 1;
                                                            }
                                                        }
                                                    }
                                                    (unsafe { *((*res).path).offset(out as isize) =
                                                        0 as i32 as i8 });
                                                    if !(unsafe { (*ref_0).path }).is_null()
                                                        && (unsafe { *((*ref_0).path)
                                                            .offset(0 as i32 as isize) })
                                                            as i32
                                                            != 0 as i32
                                                    {
                                                        indx = 0 as i32;
                                                        if out == 0 as i32
                                                            && !(unsafe { (*bas).server }).is_null()
                                                        {
                                                            let fresh134 = out;
                                                            out = out + 1;
                                                            (unsafe { *((*res).path)
                                                                .offset(fresh134 as isize) =
                                                                '/' as i32 as i8 });
                                                        }
                                                        while (unsafe { *((*ref_0).path).offset(indx as isize) })
                                                            as i32
                                                            != 0 as i32
                                                        {
                                                            let fresh135 = indx;
                                                            indx = indx + 1;
                                                            let fresh136 = out;
                                                            out = out + 1;
                                                            (unsafe { *((*res).path)
                                                                .offset(fresh136 as isize) =
                                                                *((*ref_0).path)
                                                                    .offset(fresh135 as isize) });
                                                        }
                                                    }
                                                    (unsafe { *((*res).path).offset(out as isize) =
                                                        0 as i32 as i8 });
                                                    xmlNormalizeURIPath(unsafe { (*res).path });
                                                    current_block = 17921910600917564308;
                                                }
                                            }
                                        }
                                    }
                                    match current_block {
                                        10227634464655804289 => {}
                                        _ => {
                                            val = xmlSaveUri(res);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    if !ref_0.is_null() {
        xmlFreeURI(ref_0);
    }
    if !bas.is_null() {
        xmlFreeURI(bas);
    }
    if !res.is_null() {
        xmlFreeURI(res);
    }
    return val;
}
#[no_mangle]
pub extern "C" fn xmlBuildRelativeURI(
    mut URI: *const xmlChar,
    mut base: *const xmlChar,
) -> *mut xmlChar {
    let mut current_block: u64;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    let mut ret: i32 = 0;
    let mut ix: i32 = 0;
    let mut nbslash: i32 = 0 as i32;
    let mut len: i32 = 0;
    let mut ref_0: xmlURIPtr = 0 as xmlURIPtr;
    let mut bas: xmlURIPtr = 0 as xmlURIPtr;
    let mut bptr: *mut xmlChar = 0 as *mut xmlChar;
    let mut uptr: *mut xmlChar = 0 as *mut xmlChar;
    let mut vptr: *mut xmlChar = 0 as *mut xmlChar;
    let mut remove_path: i32 = 0 as i32;
    if URI.is_null() || (unsafe { *URI }) as i32 == 0 as i32 {
        return 0 as *mut xmlChar;
    }
    ref_0 = xmlCreateURI();
    if ref_0.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { *URI.offset(0 as i32 as isize) }) as i32 != '.' as i32 {
        ret = xmlParseURIReference(ref_0, URI as *const i8);
        if ret != 0 as i32 {
            current_block = 18107649296940163300;
        } else {
            current_block = 10599921512955367680;
        }
    } else {
        let fresh137 = unsafe { &mut ((*ref_0).path) };
        *fresh137 = (unsafe { xmlStrdup(URI) }) as *mut i8;
        current_block = 10599921512955367680;
    }
    match current_block {
        10599921512955367680 => {
            if base.is_null() || (unsafe { *base }) as i32 == 0 as i32 {
                val = unsafe { xmlStrdup(URI) };
            } else {
                bas = xmlCreateURI();
                if !bas.is_null() {
                    if (unsafe { *base.offset(0 as i32 as isize) }) as i32 != '.' as i32 {
                        ret = xmlParseURIReference(bas, base as *const i8);
                        if ret != 0 as i32 {
                            current_block = 18107649296940163300;
                        } else {
                            current_block = 14576567515993809846;
                        }
                    } else {
                        let fresh138 = unsafe { &mut ((*bas).path) };
                        *fresh138 = (unsafe { xmlStrdup(base) }) as *mut i8;
                        current_block = 14576567515993809846;
                    }
                    match current_block {
                        18107649296940163300 => {}
                        _ => {
                            if !(unsafe { (*ref_0).scheme }).is_null()
                                && ((unsafe { (*bas).scheme }).is_null()
                                    || (unsafe { xmlStrcmp(
                                        (*bas).scheme as *mut xmlChar,
                                        (*ref_0).scheme as *mut xmlChar,
                                    ) }) != 0
                                    || (unsafe { xmlStrcmp(
                                        (*bas).server as *mut xmlChar,
                                        (*ref_0).server as *mut xmlChar,
                                    ) }) != 0)
                            {
                                val = unsafe { xmlStrdup(URI) };
                            } else if (unsafe { xmlStrEqual(
                                (*bas).path as *mut xmlChar,
                                (*ref_0).path as *mut xmlChar,
                            ) }) != 0
                            {
                                val = unsafe { xmlStrdup(b"\0" as *const u8 as *const i8 as *mut xmlChar) };
                            } else if (unsafe { (*bas).path }).is_null() {
                                val = unsafe { xmlStrdup((*ref_0).path as *mut xmlChar) };
                            } else {
                                if (unsafe { (*ref_0).path }).is_null() {
                                    let fresh139 = unsafe { &mut ((*ref_0).path) };
                                    *fresh139 = b"/\0" as *const u8 as *const i8 as *mut i8;
                                    remove_path = 1 as i32;
                                }
                                bptr = (unsafe { (*bas).path }) as *mut xmlChar;
                                let mut rptr: *mut xmlChar = (unsafe { (*ref_0).path }) as *mut xmlChar;
                                let mut pos: i32 = 0 as i32;
                                if (unsafe { *rptr }) as i32 == '.' as i32
                                    && (unsafe { *rptr.offset(1 as i32 as isize) }) as i32 == '/' as i32
                                {
                                    rptr = unsafe { rptr.offset(2 as i32 as isize) };
                                }
                                if (unsafe { *bptr }) as i32 == '.' as i32
                                    && (unsafe { *bptr.offset(1 as i32 as isize) }) as i32 == '/' as i32
                                {
                                    bptr = unsafe { bptr.offset(2 as i32 as isize) };
                                } else if (unsafe { *bptr }) as i32 == '/' as i32 && (unsafe { *rptr }) as i32 != '/' as i32 {
                                    bptr = unsafe { bptr.offset(1) };
                                }
                                while (unsafe { *bptr.offset(pos as isize) }) as i32
                                    == (unsafe { *rptr.offset(pos as isize) }) as i32
                                    && (unsafe { *bptr.offset(pos as isize) }) as i32 != 0 as i32
                                {
                                    pos += 1;
                                }
                                if (unsafe { *bptr.offset(pos as isize) }) as i32
                                    == (unsafe { *rptr.offset(pos as isize) }) as i32
                                {
                                    val =
                                        unsafe { xmlStrdup(b"\0" as *const u8 as *const i8 as *mut xmlChar) };
                                } else {
                                    ix = pos;
                                    while ix > 0 as i32 {
                                        if (unsafe { *rptr.offset((ix - 1 as i32) as isize) }) as i32
                                            == '/' as i32
                                        {
                                            break;
                                        }
                                        ix -= 1;
                                    }
                                    uptr = (unsafe { &mut *rptr.offset(ix as isize) }) as *mut xmlChar;
                                    while (unsafe { *bptr.offset(ix as isize) }) as i32 != 0 as i32 {
                                        if (unsafe { *bptr.offset(ix as isize) }) as i32 == '/' as i32 {
                                            nbslash += 1;
                                        }
                                        ix += 1;
                                    }
                                    if nbslash == 0 as i32 && (unsafe { *uptr.offset(0 as i32 as isize) }) == 0 {
                                        val = unsafe { xmlStrdup(
                                            b"./\0" as *const u8 as *const i8 as *mut xmlChar,
                                        ) };
                                    } else {
                                        len = (unsafe { xmlStrlen(uptr) }) + 1 as i32;
                                        if nbslash == 0 as i32 {
                                            if !uptr.is_null() {
                                                val = xmlURIEscapeStr(
                                                    uptr,
                                                    b"/;&=+$,\0" as *const u8 as *const i8
                                                        as *mut xmlChar,
                                                );
                                            }
                                        } else {
                                            val = (unsafe { xmlMalloc.expect("non-null function pointer")(
                                                (len + 3 as i32 * nbslash) as size_t,
                                            ) })
                                                as *mut xmlChar;
                                            if val.is_null() {
                                                xmlURIErrMemory(
                                                    b"building relative URI\n\0" as *const u8
                                                        as *const i8,
                                                );
                                            } else {
                                                vptr = val;
                                                while nbslash > 0 as i32 {
                                                    let fresh140 = vptr;
                                                    vptr = unsafe { vptr.offset(1) };
                                                    (unsafe { *fresh140 = '.' as i32 as xmlChar });
                                                    let fresh141 = vptr;
                                                    vptr = unsafe { vptr.offset(1) };
                                                    (unsafe { *fresh141 = '.' as i32 as xmlChar });
                                                    let fresh142 = vptr;
                                                    vptr = unsafe { vptr.offset(1) };
                                                    (unsafe { *fresh142 = '/' as i32 as xmlChar });
                                                    nbslash -= 1;
                                                }
                                                if !uptr.is_null() {
                                                    if vptr > val
                                                        && len > 0 as i32
                                                        && (unsafe { *uptr.offset(0 as i32 as isize) }) as i32
                                                            == '/' as i32
                                                        && (unsafe { *vptr.offset(-(1 as i32) as isize) }) as i32
                                                            == '/' as i32
                                                    {
                                                        (unsafe { memcpy(
                                                            vptr as *mut libc::c_void,
                                                            uptr.offset(1 as i32 as isize)
                                                                as *const libc::c_void,
                                                            (len - 1 as i32) as u64,
                                                        ) });
                                                        (unsafe { *vptr.offset((len - 2 as i32) as isize) =
                                                            0 as i32 as xmlChar });
                                                    } else {
                                                        (unsafe { memcpy(
                                                            vptr as *mut libc::c_void,
                                                            uptr as *const libc::c_void,
                                                            len as u64,
                                                        ) });
                                                        (unsafe { *vptr.offset((len - 1 as i32) as isize) =
                                                            0 as i32 as xmlChar });
                                                    }
                                                } else {
                                                    (unsafe { *vptr.offset((len - 1 as i32) as isize) =
                                                        0 as i32 as xmlChar });
                                                }
                                                vptr = val;
                                                val = xmlURIEscapeStr(
                                                    vptr,
                                                    b"/;&=+$,\0" as *const u8 as *const i8
                                                        as *mut xmlChar,
                                                );
                                                (unsafe { xmlFree.expect("non-null function pointer")(
                                                    vptr as *mut libc::c_void,
                                                ) });
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
        _ => {}
    }
    if remove_path != 0 as i32 {
        let fresh143 = unsafe { &mut ((*ref_0).path) };
        *fresh143 = 0 as *mut i8;
    }
    if !ref_0.is_null() {
        xmlFreeURI(ref_0);
    }
    if !bas.is_null() {
        xmlFreeURI(bas);
    }
    return val;
}
#[no_mangle]
pub extern "C" fn xmlCanonicPath(mut path: *const xmlChar) -> *mut xmlChar {
    let mut current_block: u64;
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut absuri: *const xmlChar = 0 as *const xmlChar;
    if path.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { *path.offset(0 as i32 as isize) }) as i32 == '/' as i32
        && (unsafe { *path.offset(1 as i32 as isize) }) as i32 == '/' as i32
        && (unsafe { *path.offset(2 as i32 as isize) }) as i32 != '/' as i32
    {
        path = unsafe { path.offset(1) };
    }
    uri = xmlParseURI(path as *const i8);
    if !uri.is_null() {
        xmlFreeURI(uri);
        return unsafe { xmlStrdup(path) };
    }
    absuri = unsafe { xmlStrstr(path, b"://\0" as *const u8 as *const i8 as *mut xmlChar) };
    if !absuri.is_null() {
        let mut l: i32 = 0;
        let mut j: i32 = 0;
        let mut c: u8 = 0;
        let mut escURI: *mut xmlChar = 0 as *mut xmlChar;
        l = (unsafe { absuri.offset_from(path) }) as i64 as i32;
        if !(l <= 0 as i32 || l > 20 as i32) {
            j = 0 as i32;
            loop {
                if !(j < l) {
                    current_block = 5948590327928692120;
                    break;
                }
                c = unsafe { *path.offset(j as isize) };
                if !(c as i32 >= 'a' as i32 && c as i32 <= 'z' as i32
                    || c as i32 >= 'A' as i32 && c as i32 <= 'Z' as i32)
                {
                    current_block = 9381984106425117681;
                    break;
                }
                j += 1;
            }
            match current_block {
                9381984106425117681 => {}
                _ => {
                    escURI = xmlURIEscapeStr(
                        path,
                        b":/?_.#&;=\0" as *const u8 as *const i8 as *mut xmlChar,
                    );
                    if !escURI.is_null() {
                        uri = xmlParseURI(escURI as *const i8);
                        if !uri.is_null() {
                            xmlFreeURI(uri);
                            return escURI;
                        }
                        (unsafe { xmlFree.expect("non-null function pointer")(escURI as *mut libc::c_void) });
                    }
                }
            }
        }
    }
    ret = unsafe { xmlStrdup(path) };
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlPathToURI(mut path: *const xmlChar) -> *mut xmlChar {
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut temp: xmlURI = xmlURI {
        scheme: 0 as *mut i8,
        opaque: 0 as *mut i8,
        authority: 0 as *mut i8,
        server: 0 as *mut i8,
        user: 0 as *mut i8,
        port: 0,
        path: 0 as *mut i8,
        query: 0 as *mut i8,
        fragment: 0 as *mut i8,
        cleanup: 0,
        query_raw: 0 as *mut i8,
    };
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut cal: *mut xmlChar = 0 as *mut xmlChar;
    if path.is_null() {
        return 0 as *mut xmlChar;
    }
    uri = xmlParseURI(path as *const i8);
    if !uri.is_null() {
        xmlFreeURI(uri);
        return unsafe { xmlStrdup(path) };
    }
    cal = xmlCanonicPath(path);
    if cal.is_null() {
        return 0 as *mut xmlChar;
    }
    (unsafe { memset(
        &mut temp as *mut xmlURI as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlURI>() as u64,
    ) });
    temp.path = cal as *mut i8;
    ret = xmlSaveUri(&mut temp);
    (unsafe { xmlFree.expect("non-null function pointer")(cal as *mut libc::c_void) });
    return ret;
}
