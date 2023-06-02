use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type _xmlBuf;
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlPattern;
    pub type _xmlStreamCtxt;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    fn snprintf(_: *mut i8, _: u64, _: *const i8, _: ...) -> i32;
    fn xmlUTF8Strlen(utf: *const xmlChar) -> i32;
    fn xmlUTF8Strsub(utf: *const xmlChar, start: i32, len: i32) -> *mut xmlChar;
    fn xmlUTF8Strloc(utf: *const xmlChar, utfchar: *const xmlChar) -> i32;
    fn xmlUTF8Strpos(utf: *const xmlChar, pos: i32) -> *const xmlChar;
    fn xmlUTF8Strsize(utf: *const xmlChar, len: i32) -> i32;
    fn xmlStrPrintf(buf: *mut xmlChar, len: i32, msg: *const i8, _: ...) -> i32;
    fn xmlStrcat(cur: *mut xmlChar, add: *const xmlChar) -> *mut xmlChar;
    fn xmlStrlen(str: *const xmlChar) -> i32;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrncmp(str1: *const xmlChar, str2: *const xmlChar, len: i32) -> i32;
    fn xmlStrstr(str: *const xmlChar, val: *const xmlChar) -> *const xmlChar;
    fn xmlStrchr(str: *const xmlChar, val: xmlChar) -> *const xmlChar;
    fn xmlStrndup(cur: *const xmlChar, len: i32) -> *mut xmlChar;
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn strlen(_: *const i8) -> u64;
    fn log10(_: f64) -> f64;
    fn pow(_: f64, _: f64) -> f64;
    fn ceil(_: f64) -> f64;
    fn fabs(_: f64) -> f64;
    fn floor(_: f64) -> f64;
    fn fmod(_: f64, _: f64) -> f64;
    fn __ctype_toupper_loc() -> *mut *const __int32_t;
    fn xmlBufContent(buf: *const xmlBuf) -> *mut xmlChar;
    fn xmlDictReference(dict: xmlDictPtr) -> i32;
    fn xmlDictFree(dict: xmlDictPtr);
    fn xmlDictLookup(dict: xmlDictPtr, name: *const xmlChar, len: i32) -> *const xmlChar;
    fn xmlBuildQName(
        ncname: *const xmlChar,
        prefix: *const xmlChar,
        memory: *mut xmlChar,
        len: i32,
    ) -> *mut xmlChar;
    fn xmlDocGetRootElement(doc: *const xmlDoc) -> xmlNodePtr;
    fn xmlFreeNodeList(cur: xmlNodePtr);
    fn xmlGetNsList(doc: *const xmlDoc, node: *const xmlNode) -> *mut xmlNsPtr;
    fn xmlNodeGetContent(cur: *const xmlNode) -> *mut xmlChar;
    fn xmlNodeGetLang(cur: *const xmlNode) -> *mut xmlChar;
    fn xmlHashCreate(size: i32) -> xmlHashTablePtr;
    fn xmlHashFree(table: xmlHashTablePtr, f: xmlHashDeallocator);
    fn xmlHashDefaultDeallocator(entry: *mut libc::c_void, name: *const xmlChar);
    fn xmlHashAddEntry(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        userdata: *mut libc::c_void,
    ) -> i32;
    fn xmlHashUpdateEntry(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        userdata: *mut libc::c_void,
        f: xmlHashDeallocator,
    ) -> i32;
    fn xmlHashAddEntry2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        name2: *const xmlChar,
        userdata: *mut libc::c_void,
    ) -> i32;
    fn xmlHashUpdateEntry2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        name2: *const xmlChar,
        userdata: *mut libc::c_void,
        f: xmlHashDeallocator,
    ) -> i32;
    fn xmlHashRemoveEntry(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        f: xmlHashDeallocator,
    ) -> i32;
    fn xmlHashRemoveEntry2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        name2: *const xmlChar,
        f: xmlHashDeallocator,
    ) -> i32;
    fn xmlHashLookup(table: xmlHashTablePtr, name: *const xmlChar) -> *mut libc::c_void;
    fn xmlHashLookup2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        name2: *const xmlChar,
    ) -> *mut libc::c_void;
    fn xmlResetError(err: xmlErrorPtr);
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
    fn xmlGetID(doc: xmlDocPtr, ID: *const xmlChar) -> xmlAttrPtr;
    fn xmlInitParser();
    fn realloc(_: *mut libc::c_void, _: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn exit(_: i32) -> !;
    static mut xmlMalloc: xmlMallocFunc;
    static mut xmlMallocAtomic: xmlMallocFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlFree: xmlFreeFunc;
    fn __xmlGenericError() -> *mut xmlGenericErrorFunc;
    fn __xmlGenericErrorContext() -> *mut *mut libc::c_void;
    fn xmlCopyChar(len: i32, out: *mut xmlChar, val: i32) -> i32;
    static xmlIsExtenderGroup: xmlChRangeGroup;
    fn xmlCharInRange(val: u32, group: *const xmlChRangeGroup) -> i32;
    static xmlIsCombiningGroup: xmlChRangeGroup;
    static xmlIsDigitGroup: xmlChRangeGroup;
    static xmlIsBaseCharGroup: xmlChRangeGroup;
    fn xmlDebugDumpString(output: *mut FILE, str: *const xmlChar);
    fn xmlDebugDumpAttr(output: *mut FILE, attr: xmlAttrPtr, depth: i32);
    fn xmlDebugDumpOneNode(output: *mut FILE, node: xmlNodePtr, depth: i32);
    fn xmlFreePattern(comp: xmlPatternPtr);
    fn xmlFreePatternList(comp: xmlPatternPtr);
    fn xmlPatterncompile(
        pattern: *const xmlChar,
        dict: *mut xmlDict,
        flags: i32,
        namespaces: *mut *const xmlChar,
    ) -> xmlPatternPtr;
    fn xmlPatternStreamable(comp: xmlPatternPtr) -> i32;
    fn xmlPatternMaxDepth(comp: xmlPatternPtr) -> i32;
    fn xmlPatternMinDepth(comp: xmlPatternPtr) -> i32;
    fn xmlPatternFromRoot(comp: xmlPatternPtr) -> i32;
    fn xmlPatternGetStreamCtxt(comp: xmlPatternPtr) -> xmlStreamCtxtPtr;
    fn xmlFreeStreamCtxt(stream: xmlStreamCtxtPtr);
    fn xmlStreamPushNode(
        stream: xmlStreamCtxtPtr,
        name: *const xmlChar,
        ns: *const xmlChar,
        nodeType: i32,
    ) -> i32;
    fn xmlStreamPush(stream: xmlStreamCtxtPtr, name: *const xmlChar, ns: *const xmlChar) -> i32;
    fn xmlStreamPop(stream: xmlStreamCtxtPtr) -> i32;
    fn xmlStreamWantsAnyNode(stream: xmlStreamCtxtPtr) -> i32;
    fn xmlBufCreate() -> xmlBufPtr;
    fn xmlBufFree(buf: xmlBufPtr);
    fn xmlBufAdd(buf: xmlBufPtr, str: *const xmlChar, len: i32) -> i32;
}
pub type xmlChar = u8;
pub type size_t = u64;
pub type __int32_t = i32;
pub type __uint64_t = u64;
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
pub type ptrdiff_t = i64;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type xmlReallocFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void>;
pub type xmlBufPtr = *mut xmlBuf;
pub type xmlBuf = _xmlBuf;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNode {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlNode,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub ns: *mut xmlNs,
    pub content: *mut xmlChar,
    pub properties: *mut _xmlAttr,
    pub nsDef: *mut xmlNs,
    pub psvi: *mut libc::c_void,
    pub line: u16,
    pub extra: u16,
}
pub type xmlNs = _xmlNs;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNs {
    pub next: *mut _xmlNs,
    pub type_0: xmlNsType,
    pub href: *const xmlChar,
    pub prefix: *const xmlChar,
    pub _private: *mut libc::c_void,
    pub context: *mut _xmlDoc,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDoc {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *mut i8,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlNode,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub compression: i32,
    pub standalone: i32,
    pub intSubset: *mut _xmlDtd,
    pub extSubset: *mut _xmlDtd,
    pub oldNs: *mut _xmlNs,
    pub version: *const xmlChar,
    pub encoding: *const xmlChar,
    pub ids: *mut libc::c_void,
    pub refs: *mut libc::c_void,
    pub URL: *const xmlChar,
    pub charset: i32,
    pub dict: *mut _xmlDict,
    pub psvi: *mut libc::c_void,
    pub parseFlags: i32,
    pub properties: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDtd {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlDoc,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub notations: *mut libc::c_void,
    pub elements: *mut libc::c_void,
    pub attributes: *mut libc::c_void,
    pub entities: *mut libc::c_void,
    pub ExternalID: *const xmlChar,
    pub SystemID: *const xmlChar,
    pub pentities: *mut libc::c_void,
}
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
pub type xmlNsType = xmlElementType;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlAttr {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlNode,
    pub next: *mut _xmlAttr,
    pub prev: *mut _xmlAttr,
    pub doc: *mut _xmlDoc,
    pub ns: *mut xmlNs,
    pub atype: xmlAttributeType,
    pub psvi: *mut libc::c_void,
}
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
pub type xmlAttrPtr = *mut xmlAttr;
pub type xmlAttr = _xmlAttr;
pub type xmlNodePtr = *mut xmlNode;
pub type xmlNode = _xmlNode;
pub type xmlHashTablePtr = *mut xmlHashTable;
pub type xmlHashTable = _xmlHashTable;
pub type xmlDictPtr = *mut xmlDict;
pub type xmlDict = _xmlDict;
pub type xmlDocPtr = *mut xmlDoc;
pub type xmlDoc = _xmlDoc;
pub type xmlStructuredErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> ()>;
pub type xmlErrorPtr = *mut xmlError;
pub type xmlNsPtr = *mut xmlNs;
pub type xmlHashDeallocator = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
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
pub type xmlXPathFuncLookupFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> xmlXPathFunction,
>;
pub type xmlXPathFunction = Option<unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()>;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathCompExpr {
    pub nbStep: i32,
    pub maxStep: i32,
    pub steps: *mut xmlXPathStepOp,
    pub last: i32,
    pub expr: *mut xmlChar,
    pub dict: xmlDictPtr,
    pub stream: xmlPatternPtr,
}
pub type xmlPatternPtr = *mut xmlPattern;
pub type xmlPattern = _xmlPattern;
pub type xmlXPathStepOp = _xmlXPathStepOp;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathStepOp {
    pub op: xmlXPathOp,
    pub ch1: i32,
    pub ch2: i32,
    pub value: i32,
    pub value2: i32,
    pub value3: i32,
    pub value4: *mut libc::c_void,
    pub value5: *mut libc::c_void,
    pub cache: xmlXPathFunction,
    pub cacheURI: *mut libc::c_void,
}
pub type xmlXPathOp = u32;
pub const XPATH_OP_SORT: xmlXPathOp = 17;
pub const XPATH_OP_FILTER: xmlXPathOp = 16;
pub const XPATH_OP_PREDICATE: xmlXPathOp = 15;
pub const XPATH_OP_ARG: xmlXPathOp = 14;
pub const XPATH_OP_FUNCTION: xmlXPathOp = 13;
pub const XPATH_OP_VARIABLE: xmlXPathOp = 12;
pub const XPATH_OP_VALUE: xmlXPathOp = 11;
pub const XPATH_OP_COLLECT: xmlXPathOp = 10;
pub const XPATH_OP_NODE: xmlXPathOp = 9;
pub const XPATH_OP_ROOT: xmlXPathOp = 8;
pub const XPATH_OP_UNION: xmlXPathOp = 7;
pub const XPATH_OP_MULT: xmlXPathOp = 6;
pub const XPATH_OP_PLUS: xmlXPathOp = 5;
pub const XPATH_OP_CMP: xmlXPathOp = 4;
pub const XPATH_OP_EQUAL: xmlXPathOp = 3;
pub const XPATH_OP_OR: xmlXPathOp = 2;
pub const XPATH_OP_AND: xmlXPathOp = 1;
pub const XPATH_OP_END: xmlXPathOp = 0;
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
pub type xmlNodeSetPtr = *mut xmlNodeSet;
pub type xmlNodeSet = _xmlNodeSet;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNodeSet {
    pub nodeNr: i32,
    pub nodeMax: i32,
    pub nodeTab: *mut xmlNodePtr,
}
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
pub type xmlXPathVariableLookupFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> xmlXPathObjectPtr,
>;
pub type xmlXPathAxisPtr = *mut xmlXPathAxis;
pub type xmlXPathAxis = _xmlXPathAxis;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathAxis {
    pub name: *const xmlChar,
    pub func: xmlXPathAxisFunc,
}
pub type xmlXPathAxisFunc =
    Option<unsafe extern "C" fn(xmlXPathParserContextPtr, xmlXPathObjectPtr) -> xmlXPathObjectPtr>;
pub type xmlXPathTypePtr = *mut xmlXPathType;
pub type xmlXPathType = _xmlXPathType;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathType {
    pub name: *const xmlChar,
    pub func: xmlXPathConvertFunc,
}
pub type xmlXPathConvertFunc = Option<unsafe extern "C" fn(xmlXPathObjectPtr, i32) -> i32>;
pub type C2RustUnnamed_1 = u32;
pub const XPATH_RECURSION_LIMIT_EXCEEDED: C2RustUnnamed_1 = 26;
pub const XPATH_OP_LIMIT_EXCEEDED: C2RustUnnamed_1 = 25;
pub const XPATH_FORBID_VARIABLE_ERROR: C2RustUnnamed_1 = 24;
pub const XPATH_STACK_ERROR: C2RustUnnamed_1 = 23;
pub const XPATH_INVALID_CTXT: C2RustUnnamed_1 = 22;
pub const XPATH_INVALID_CHAR_ERROR: C2RustUnnamed_1 = 21;
pub const XPATH_ENCODING_ERROR: C2RustUnnamed_1 = 20;
pub const XPATH_UNDEF_PREFIX_ERROR: C2RustUnnamed_1 = 19;
pub const XPTR_SUB_RESOURCE_ERROR: C2RustUnnamed_1 = 18;
pub const XPTR_RESOURCE_ERROR: C2RustUnnamed_1 = 17;
pub const XPTR_SYNTAX_ERROR: C2RustUnnamed_1 = 16;
pub const XPATH_MEMORY_ERROR: C2RustUnnamed_1 = 15;
pub const XPATH_INVALID_CTXT_POSITION: C2RustUnnamed_1 = 14;
pub const XPATH_INVALID_CTXT_SIZE: C2RustUnnamed_1 = 13;
pub const XPATH_INVALID_ARITY: C2RustUnnamed_1 = 12;
pub const XPATH_INVALID_TYPE: C2RustUnnamed_1 = 11;
pub const XPATH_INVALID_OPERAND: C2RustUnnamed_1 = 10;
pub const XPATH_UNKNOWN_FUNC_ERROR: C2RustUnnamed_1 = 9;
pub const XPATH_UNCLOSED_ERROR: C2RustUnnamed_1 = 8;
pub const XPATH_EXPR_ERROR: C2RustUnnamed_1 = 7;
pub const XPATH_INVALID_PREDICATE_ERROR: C2RustUnnamed_1 = 6;
pub const XPATH_UNDEF_VARIABLE_ERROR: C2RustUnnamed_1 = 5;
pub const XPATH_VARIABLE_REF_ERROR: C2RustUnnamed_1 = 4;
pub const XPATH_START_LITERAL_ERROR: C2RustUnnamed_1 = 3;
pub const XPATH_UNFINISHED_LITERAL_ERROR: C2RustUnnamed_1 = 2;
pub const XPATH_NUMBER_ERROR: C2RustUnnamed_1 = 1;
pub const XPATH_EXPRESSION_OK: C2RustUnnamed_1 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TIM_SORT_RUN_T {
    pub start: size_t,
    pub length: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TEMP_STORAGE_T {
    pub alloc: size_t,
    pub storage: *mut xmlNodePtr,
}
pub type uint64_t = __uint64_t;
pub type xmlPointerListPtr = *mut xmlPointerList;
pub type xmlPointerList = _xmlPointerList;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlPointerList {
    pub items: *mut *mut libc::c_void,
    pub number: i32,
    pub size: i32,
}
pub type xmlXPathContextCachePtr = *mut xmlXPathContextCache;
pub type xmlXPathContextCache = _xmlXPathContextCache;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathContextCache {
    pub nodesetObjs: xmlPointerListPtr,
    pub stringObjs: xmlPointerListPtr,
    pub booleanObjs: xmlPointerListPtr,
    pub numberObjs: xmlPointerListPtr,
    pub miscObjs: xmlPointerListPtr,
    pub maxNodeset: i32,
    pub maxString: i32,
    pub maxBoolean: i32,
    pub maxNumber: i32,
    pub maxMisc: i32,
}
pub type xmlXPathStepOpPtr = *mut xmlXPathStepOp;
pub type xmlXPathNodeSetMergeFunction =
    Option<unsafe extern "C" fn(xmlNodeSetPtr, xmlNodeSetPtr) -> xmlNodeSetPtr>;
pub const AXIS_NAMESPACE: xmlXPathAxisVal = 9;
pub type xmlXPathAxisVal = u32;
pub const AXIS_SELF: xmlXPathAxisVal = 13;
pub const AXIS_PRECEDING_SIBLING: xmlXPathAxisVal = 12;
pub const AXIS_PRECEDING: xmlXPathAxisVal = 11;
pub const AXIS_PARENT: xmlXPathAxisVal = 10;
pub const AXIS_FOLLOWING_SIBLING: xmlXPathAxisVal = 8;
pub const AXIS_FOLLOWING: xmlXPathAxisVal = 7;
pub const AXIS_DESCENDANT_OR_SELF: xmlXPathAxisVal = 6;
pub const AXIS_DESCENDANT: xmlXPathAxisVal = 5;
pub const AXIS_CHILD: xmlXPathAxisVal = 4;
pub const AXIS_ATTRIBUTE: xmlXPathAxisVal = 3;
pub const AXIS_ANCESTOR_OR_SELF: xmlXPathAxisVal = 2;
pub const AXIS_ANCESTOR: xmlXPathAxisVal = 1;
pub const NODE_TEST_NAME: xmlXPathTestVal = 5;
pub const NODE_TEST_NS: xmlXPathTestVal = 4;
pub const NODE_TEST_ALL: xmlXPathTestVal = 3;
pub const NODE_TEST_PI: xmlXPathTestVal = 2;
pub const NODE_TYPE_TEXT: xmlXPathTypeVal = 3;
pub type xmlXPathTypeVal = u32;
pub const NODE_TYPE_PI: xmlXPathTypeVal = 7;
pub const NODE_TYPE_COMMENT: xmlXPathTypeVal = 8;
pub const NODE_TYPE_NODE: xmlXPathTypeVal = 0;
pub const NODE_TEST_TYPE: xmlXPathTestVal = 1;
pub const NODE_TEST_NONE: xmlXPathTestVal = 0;
pub type xmlXPathTestVal = u32;
pub type xmlXPathTraversalFunction =
    Option<unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr>;
pub type xmlStreamCtxtPtr = *mut xmlStreamCtxt;
pub type xmlStreamCtxt = _xmlStreamCtxt;
pub type xmlChRangeGroup = _xmlChRangeGroup;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChRangeGroup {
    pub nbShortRange: i32,
    pub nbLongRange: i32,
    pub shortRange: *const xmlChSRange,
    pub longRange: *const xmlChLRange,
}
pub type xmlChLRange = _xmlChLRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChLRange {
    pub low: u32,
    pub high: u32,
}
pub type xmlChSRange = _xmlChSRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChSRange {
    pub low: u16,
    pub high: u16,
}
pub const XML_PATTERN_XPATH: C2RustUnnamed_2 = 1;
pub type C2RustUnnamed_2 = u32;
pub const XML_PATTERN_XSFIELD: C2RustUnnamed_2 = 4;
pub const XML_PATTERN_XSSEL: C2RustUnnamed_2 = 2;
pub const XML_PATTERN_DEFAULT: C2RustUnnamed_2 = 0;
#[inline]
extern "C" fn toupper(mut __c: i32) -> i32 {
    return if __c >= -(128 as i32) && __c < 256 as i32 {
        unsafe { *(*__ctype_toupper_loc()).offset(__c as isize) }
    } else {
        __c
    };
}
extern "C" fn xmlXPathCmpNodesExt(mut node1: xmlNodePtr, mut node2: xmlNodePtr) -> i32 {
    let mut current_block: u64;
    let mut depth1: i32 = 0;
    let mut depth2: i32 = 0;
    let mut misc: i32 = 0 as i32;
    let mut precedence1: i32 = 0 as i32;
    let mut precedence2: i32 = 0 as i32;
    let mut miscNode1: xmlNodePtr = 0 as xmlNodePtr;
    let mut miscNode2: xmlNodePtr = 0 as xmlNodePtr;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut root: xmlNodePtr = 0 as *mut xmlNode;
    let mut l1: ptrdiff_t = 0;
    let mut l2: ptrdiff_t = 0;
    if node1.is_null() || node2.is_null() {
        return -(2 as i32);
    }
    if node1 == node2 {
        return 0 as i32;
    }
    match (unsafe { (*node1).type_0 }) as u32 {
        1 => {
            if (unsafe { (*node2).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                if 0 as i32 as i64 > (unsafe { (*node1).content }) as ptrdiff_t
                    && 0 as i32 as i64 > (unsafe { (*node2).content }) as ptrdiff_t
                    && (unsafe { (*node1).doc }) == (unsafe { (*node2).doc })
                {
                    l1 = -((unsafe { (*node1).content }) as ptrdiff_t);
                    l2 = -((unsafe { (*node2).content }) as ptrdiff_t);
                    if l1 < l2 {
                        return 1 as i32;
                    }
                    if l1 > l2 {
                        return -(1 as i32);
                    }
                    current_block = 721385680381463314;
                } else {
                    current_block = 9535040653783544971;
                }
            } else {
                current_block = 721385680381463314;
            }
        }
        2 => {
            precedence1 = 1 as i32;
            miscNode1 = node1;
            node1 = unsafe { (*node1).parent };
            misc = 1 as i32;
            current_block = 721385680381463314;
        }
        3 | 4 | 8 | 7 => {
            miscNode1 = node1;
            if !(unsafe { (*node1).prev }).is_null() {
                loop {
                    node1 = unsafe { (*node1).prev };
                    if (unsafe { (*node1).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                        precedence1 = 3 as i32;
                        break;
                    } else {
                        if !(unsafe { (*node1).prev }).is_null() {
                            continue;
                        }
                        precedence1 = 2 as i32;
                        node1 = unsafe { (*node1).parent };
                        break;
                    }
                }
            } else {
                precedence1 = 2 as i32;
                node1 = unsafe { (*node1).parent };
            }
            if node1.is_null()
                || (unsafe { (*node1).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
                || 0 as i32 as i64 <= (unsafe { (*node1).content }) as ptrdiff_t
            {
                node1 = miscNode1;
                precedence1 = 0 as i32;
            } else {
                misc = 1 as i32;
            }
            current_block = 721385680381463314;
        }
        18 => return 1 as i32,
        _ => {
            current_block = 721385680381463314;
        }
    }
    match current_block {
        721385680381463314 => {
            match (unsafe { (*node2).type_0 }) as u32 {
                2 => {
                    precedence2 = 1 as i32;
                    miscNode2 = node2;
                    node2 = unsafe { (*node2).parent };
                    misc = 1 as i32;
                }
                3 | 4 | 8 | 7 => {
                    miscNode2 = node2;
                    if !(unsafe { (*node2).prev }).is_null() {
                        loop {
                            node2 = unsafe { (*node2).prev };
                            if (unsafe { (*node2).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                                precedence2 = 3 as i32;
                                break;
                            } else {
                                if !(unsafe { (*node2).prev }).is_null() {
                                    continue;
                                }
                                precedence2 = 2 as i32;
                                node2 = unsafe { (*node2).parent };
                                break;
                            }
                        }
                    } else {
                        precedence2 = 2 as i32;
                        node2 = unsafe { (*node2).parent };
                    }
                    if node2.is_null()
                        || (unsafe { (*node2).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
                        || 0 as i32 as i64 <= (unsafe { (*node2).content }) as ptrdiff_t
                    {
                        node2 = miscNode2;
                        precedence2 = 0 as i32;
                    } else {
                        misc = 1 as i32;
                    }
                }
                18 => return 1 as i32,
                1 | _ => {}
            }
            if misc != 0 {
                if node1 == node2 {
                    if precedence1 == precedence2 {
                        cur = unsafe { (*miscNode2).prev };
                        while !cur.is_null() {
                            if cur == miscNode1 {
                                return 1 as i32;
                            }
                            if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                                return -(1 as i32);
                            }
                            cur = unsafe { (*cur).prev };
                        }
                        return -(1 as i32);
                    } else if precedence1 < precedence2 {
                        return 1 as i32;
                    } else {
                        return -(1 as i32);
                    }
                }
                if precedence2 == 3 as i32 && precedence1 > 1 as i32 {
                    cur = unsafe { (*node1).parent };
                    while !cur.is_null() {
                        if cur == node2 {
                            return 1 as i32;
                        }
                        cur = unsafe { (*cur).parent };
                    }
                }
                if precedence1 == 3 as i32 && precedence2 > 1 as i32 {
                    cur = unsafe { (*node2).parent };
                    while !cur.is_null() {
                        if cur == node1 {
                            return -(1 as i32);
                        }
                        cur = unsafe { (*cur).parent };
                    }
                }
            }
            if (unsafe { (*node1).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                && (unsafe { (*node2).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                && 0 as i32 as i64 > (unsafe { (*node1).content }) as ptrdiff_t
                && 0 as i32 as i64 > (unsafe { (*node2).content }) as ptrdiff_t
                && (unsafe { (*node1).doc }) == (unsafe { (*node2).doc })
            {
                l1 = -((unsafe { (*node1).content }) as ptrdiff_t);
                l2 = -((unsafe { (*node2).content }) as ptrdiff_t);
                if l1 < l2 {
                    return 1 as i32;
                }
                if l1 > l2 {
                    return -(1 as i32);
                }
            }
        }
        _ => {}
    }
    if node1 == (unsafe { (*node2).prev }) {
        return 1 as i32;
    }
    if node1 == (unsafe { (*node2).next }) {
        return -(1 as i32);
    }
    depth2 = 0 as i32;
    cur = node2;
    while !(unsafe { (*cur).parent }).is_null() {
        if (unsafe { (*cur).parent }) == node1 {
            return 1 as i32;
        }
        depth2 += 1;
        cur = unsafe { (*cur).parent };
    }
    root = cur;
    depth1 = 0 as i32;
    cur = node1;
    while !(unsafe { (*cur).parent }).is_null() {
        if (unsafe { (*cur).parent }) == node2 {
            return -(1 as i32);
        }
        depth1 += 1;
        cur = unsafe { (*cur).parent };
    }
    if root != cur {
        return -(2 as i32);
    }
    while depth1 > depth2 {
        depth1 -= 1;
        node1 = unsafe { (*node1).parent };
    }
    while depth2 > depth1 {
        depth2 -= 1;
        node2 = unsafe { (*node2).parent };
    }
    while (unsafe { (*node1).parent }) != (unsafe { (*node2).parent }) {
        node1 = unsafe { (*node1).parent };
        node2 = unsafe { (*node2).parent };
        if node1.is_null() || node2.is_null() {
            return -(2 as i32);
        }
    }
    if node1 == (unsafe { (*node2).prev }) {
        return 1 as i32;
    }
    if node1 == (unsafe { (*node2).next }) {
        return -(1 as i32);
    }
    if (unsafe { (*node1).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
        && (unsafe { (*node2).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
        && 0 as i32 as i64 > (unsafe { (*node1).content }) as ptrdiff_t
        && 0 as i32 as i64 > (unsafe { (*node2).content }) as ptrdiff_t
        && (unsafe { (*node1).doc }) == (unsafe { (*node2).doc })
    {
        l1 = -((unsafe { (*node1).content }) as ptrdiff_t);
        l2 = -((unsafe { (*node2).content }) as ptrdiff_t);
        if l1 < l2 {
            return 1 as i32;
        }
        if l1 > l2 {
            return -(1 as i32);
        }
    }
    cur = unsafe { (*node1).next };
    while !cur.is_null() {
        if cur == node2 {
            return 1 as i32;
        }
        cur = unsafe { (*cur).next };
    }
    return -(1 as i32);
}
extern "C" fn wrap_cmp(mut x: xmlNodePtr, mut y: xmlNodePtr) -> i32 {
    let mut res: i32 = xmlXPathCmpNodesExt(x, y);
    return if res == -(2 as i32) { res } else { -res };
}
#[inline]
extern "C" fn compute_minrun(size: uint64_t) -> i32 {
    let top_bit: i32 = 64 as i32 - (size as u64).leading_zeros() as i32;
    let shift: i32 = (if top_bit > 6 as i32 {
        top_bit
    } else {
        6 as i32
    }) - 6 as i32;
    let minrun: i32 = (size >> shift) as i32;
    let mask: uint64_t = ((1 as u64) << shift).wrapping_sub(1 as i32 as u64) as uint64_t;
    if mask & size != 0 {
        return minrun + 1 as i32;
    }
    return minrun;
}
#[inline]
extern "C" fn libxml_domnode_binary_insertion_find(
    mut dst: *mut xmlNodePtr,
    x: xmlNodePtr,
    size: size_t,
) -> size_t {
    let mut l: size_t = 0;
    let mut c: size_t = 0;
    let mut r: size_t = 0;
    let mut cx: xmlNodePtr = 0 as *mut xmlNode;
    l = 0 as i32 as size_t;
    r = size.wrapping_sub(1 as i32 as u64);
    c = r >> 1 as i32;
    if wrap_cmp(x, unsafe { *dst.offset(0 as i32 as isize) }) < 0 as i32 {
        return 0 as i32 as size_t;
    } else {
        if wrap_cmp(x, unsafe { *dst.offset(r as isize) }) > 0 as i32 {
            return r;
        }
    }
    cx = unsafe { *dst.offset(c as isize) };
    loop {
        let val: i32 = wrap_cmp(x, cx);
        if val < 0 as i32 {
            if c.wrapping_sub(l) <= 1 as i32 as u64 {
                return c;
            }
            r = c;
        } else {
            if r.wrapping_sub(c) <= 1 as i32 as u64 {
                return c.wrapping_add(1 as i32 as u64);
            }
            l = c;
        }
        c = l.wrapping_add(r.wrapping_sub(l) >> 1 as i32);
        cx = unsafe { *dst.offset(c as isize) };
    }
}
extern "C" fn libxml_domnode_binary_insertion_sort_start(
    mut dst: *mut xmlNodePtr,
    start: size_t,
    size: size_t,
) {
    let mut i: size_t = 0;
    i = start;
    while i < size {
        let mut j: size_t = 0;
        let mut x: xmlNodePtr = 0 as *mut xmlNode;
        let mut location: size_t = 0;
        if !(wrap_cmp(
            unsafe { *dst.offset(i.wrapping_sub(1 as i32 as u64) as isize) },
            unsafe { *dst.offset(i as isize) },
        ) <= 0 as i32)
        {
            x = unsafe { *dst.offset(i as isize) };
            location = libxml_domnode_binary_insertion_find(dst, x, i);
            j = i.wrapping_sub(1 as i32 as u64);
            while j >= location {
                let fresh0 = unsafe { &mut (*dst.offset(j.wrapping_add(1 as i32 as u64) as isize)) };
                *fresh0 = unsafe { *dst.offset(j as isize) };
                if j == 0 as i32 as u64 {
                    break;
                }
                j = j.wrapping_sub(1);
            }
            let fresh1 = unsafe { &mut (*dst.offset(location as isize)) };
            *fresh1 = x;
        }
        i = i.wrapping_add(1);
    }
}
#[no_mangle]
pub extern "C" fn libxml_domnode_binary_insertion_sort(mut dst: *mut xmlNodePtr, size: size_t) {
    if size <= 1 as i32 as u64 {
        return;
    }
    libxml_domnode_binary_insertion_sort_start(dst, 1 as i32 as size_t, size);
}
#[inline]
extern "C" fn libxml_domnode_reverse_elements(
    mut dst: *mut xmlNodePtr,
    mut start: size_t,
    mut end: size_t,
) {
    loop {
        if start >= end {
            return;
        }
        let mut __SORT_SWAP_t: xmlNodePtr = unsafe { *dst.offset(start as isize) };
        let fresh2 = unsafe { &mut (*dst.offset(start as isize)) };
        *fresh2 = unsafe { *dst.offset(end as isize) };
        let fresh3 = unsafe { &mut (*dst.offset(end as isize)) };
        *fresh3 = __SORT_SWAP_t;
        start = start.wrapping_add(1);
        end = end.wrapping_sub(1);
    }
}
extern "C" fn libxml_domnode_count_run(
    mut dst: *mut xmlNodePtr,
    start: size_t,
    size: size_t,
) -> size_t {
    let mut curr: size_t = 0;
    if size.wrapping_sub(start) == 1 as i32 as u64 {
        return 1 as i32 as size_t;
    }
    if start >= size.wrapping_sub(2 as i32 as u64) {
        if wrap_cmp(
            unsafe { *dst.offset(size.wrapping_sub(2 as i32 as u64) as isize) },
            unsafe { *dst.offset(size.wrapping_sub(1 as i32 as u64) as isize) },
        ) > 0 as i32
        {
            let mut __SORT_SWAP_t: xmlNodePtr =
                unsafe { *dst.offset(size.wrapping_sub(2 as i32 as u64) as isize) };
            let fresh4 = unsafe { &mut (*dst.offset(size.wrapping_sub(2 as i32 as u64) as isize)) };
            *fresh4 = unsafe { *dst.offset(size.wrapping_sub(1 as i32 as u64) as isize) };
            let fresh5 = unsafe { &mut (*dst.offset(size.wrapping_sub(1 as i32 as u64) as isize)) };
            *fresh5 = __SORT_SWAP_t;
        }
        return 2 as i32 as size_t;
    }
    curr = start.wrapping_add(2 as i32 as u64);
    if wrap_cmp(
        unsafe { *dst.offset(start as isize) },
        unsafe { *dst.offset(start.wrapping_add(1 as i32 as u64) as isize) },
    ) <= 0 as i32
    {
        while !(curr == size.wrapping_sub(1 as i32 as u64)) {
            if wrap_cmp(
                unsafe { *dst.offset(curr.wrapping_sub(1 as i32 as u64) as isize) },
                unsafe { *dst.offset(curr as isize) },
            ) > 0 as i32
            {
                break;
            }
            curr = curr.wrapping_add(1);
        }
        return curr.wrapping_sub(start);
    } else {
        while !(curr == size.wrapping_sub(1 as i32 as u64)) {
            if wrap_cmp(
                unsafe { *dst.offset(curr.wrapping_sub(1 as i32 as u64) as isize) },
                unsafe { *dst.offset(curr as isize) },
            ) <= 0 as i32
            {
                break;
            }
            curr = curr.wrapping_add(1);
        }
        libxml_domnode_reverse_elements(dst, start, curr.wrapping_sub(1 as i32 as u64));
        return curr.wrapping_sub(start);
    };
}
extern "C" fn libxml_domnode_check_invariant(
    mut stack: *mut TIM_SORT_RUN_T,
    stack_curr: i32,
) -> i32 {
    let mut A: size_t = 0;
    let mut B: size_t = 0;
    let mut C: size_t = 0;
    if stack_curr < 2 as i32 {
        return 1 as i32;
    }
    if stack_curr == 2 as i32 {
        let A1: size_t = unsafe { (*stack.offset((stack_curr - 2 as i32) as isize)).length };
        let B1: size_t = unsafe { (*stack.offset((stack_curr - 1 as i32) as isize)).length };
        if A1 <= B1 {
            return 0 as i32;
        }
        return 1 as i32;
    }
    A = unsafe { (*stack.offset((stack_curr - 3 as i32) as isize)).length };
    B = unsafe { (*stack.offset((stack_curr - 2 as i32) as isize)).length };
    C = unsafe { (*stack.offset((stack_curr - 1 as i32) as isize)).length };
    if A <= B.wrapping_add(C) || B <= C {
        return 0 as i32;
    }
    return 1 as i32;
}
extern "C" fn libxml_domnode_tim_sort_resize(mut store: *mut TEMP_STORAGE_T, new_size: size_t) {
    if (unsafe { (*store).alloc }) < new_size {
        let mut tempstore: *mut xmlNodePtr = (unsafe { realloc(
            (*store).storage as *mut libc::c_void,
            new_size.wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) }) as *mut xmlNodePtr;
        if tempstore.is_null() {
            (unsafe { fprintf(
                stderr,
                b"Error allocating temporary storage for tim sort: need %lu bytes\0" as *const u8
                    as *const i8,
                (::std::mem::size_of::<xmlNodePtr>() as u64).wrapping_mul(new_size),
            ) });
            (unsafe { exit(1 as i32) });
        }
        let fresh6 = unsafe { &mut ((*store).storage) };
        *fresh6 = tempstore;
        (unsafe { (*store).alloc = new_size });
    }
}
extern "C" fn libxml_domnode_tim_sort_merge(
    mut dst: *mut xmlNodePtr,
    mut stack: *const TIM_SORT_RUN_T,
    stack_curr: i32,
    mut store: *mut TEMP_STORAGE_T,
) {
    let A: size_t = unsafe { (*stack.offset((stack_curr - 2 as i32) as isize)).length };
    let B: size_t = unsafe { (*stack.offset((stack_curr - 1 as i32) as isize)).length };
    let curr: size_t = unsafe { (*stack.offset((stack_curr - 2 as i32) as isize)).start };
    let mut storage: *mut xmlNodePtr = 0 as *mut xmlNodePtr;
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut k: size_t = 0;
    libxml_domnode_tim_sort_resize(store, if A < B { A } else { B });
    storage = unsafe { (*store).storage };
    if A < B {
        (unsafe { memcpy(
            storage as *mut libc::c_void,
            &mut *dst.offset(curr as isize) as *mut xmlNodePtr as *const libc::c_void,
            A.wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) });
        i = 0 as i32 as size_t;
        j = curr.wrapping_add(A);
        k = curr;
        while k < curr.wrapping_add(A).wrapping_add(B) {
            if i < A && j < curr.wrapping_add(A).wrapping_add(B) {
                if wrap_cmp(unsafe { *storage.offset(i as isize) }, unsafe { *dst.offset(j as isize) }) <= 0 as i32 {
                    let fresh7 = i;
                    i = i.wrapping_add(1);
                    let fresh8 = unsafe { &mut (*dst.offset(k as isize)) };
                    *fresh8 = unsafe { *storage.offset(fresh7 as isize) };
                } else {
                    let fresh9 = j;
                    j = j.wrapping_add(1);
                    let fresh10 = unsafe { &mut (*dst.offset(k as isize)) };
                    *fresh10 = unsafe { *dst.offset(fresh9 as isize) };
                }
            } else {
                if !(i < A) {
                    break;
                }
                let fresh11 = i;
                i = i.wrapping_add(1);
                let fresh12 = unsafe { &mut (*dst.offset(k as isize)) };
                *fresh12 = unsafe { *storage.offset(fresh11 as isize) };
            }
            k = k.wrapping_add(1);
        }
    } else {
        (unsafe { memcpy(
            storage as *mut libc::c_void,
            &mut *dst.offset(curr.wrapping_add(A) as isize) as *mut xmlNodePtr
                as *const libc::c_void,
            B.wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) });
        i = B;
        j = curr.wrapping_add(A);
        k = curr.wrapping_add(A).wrapping_add(B);
        while k > curr {
            k = k.wrapping_sub(1);
            if i > 0 as i32 as u64 && j > curr {
                if wrap_cmp(
                    unsafe { *dst.offset(j.wrapping_sub(1 as i32 as u64) as isize) },
                    unsafe { *storage.offset(i.wrapping_sub(1 as i32 as u64) as isize) },
                ) > 0 as i32
                {
                    j = j.wrapping_sub(1);
                    let fresh13 = unsafe { &mut (*dst.offset(k as isize)) };
                    *fresh13 = unsafe { *dst.offset(j as isize) };
                } else {
                    i = i.wrapping_sub(1);
                    let fresh14 = unsafe { &mut (*dst.offset(k as isize)) };
                    *fresh14 = unsafe { *storage.offset(i as isize) };
                }
            } else {
                if !(i > 0 as i32 as u64) {
                    break;
                }
                i = i.wrapping_sub(1);
                let fresh15 = unsafe { &mut (*dst.offset(k as isize)) };
                *fresh15 = unsafe { *storage.offset(i as isize) };
            }
        }
    };
}
#[no_mangle]
pub extern "C" fn libxml_domnode_tim_sort(mut dst: *mut xmlNodePtr, size: size_t) {
    let mut minrun: size_t = 0;
    let mut _store: TEMP_STORAGE_T = TEMP_STORAGE_T {
        alloc: 0,
        storage: 0 as *mut xmlNodePtr,
    };
    let mut store: *mut TEMP_STORAGE_T = 0 as *mut TEMP_STORAGE_T;
    let mut run_stack: [TIM_SORT_RUN_T; 128] = [TIM_SORT_RUN_T {
        start: 0,
        length: 0,
    }; 128];
    let mut stack_curr: size_t = 0 as i32 as size_t;
    let mut curr: size_t = 0 as i32 as size_t;
    if size <= 1 as i32 as u64 {
        return;
    }
    if size < 64 as i32 as u64 {
        libxml_domnode_binary_insertion_sort(dst, size);
        return;
    }
    minrun = compute_minrun(size) as size_t;
    store = &mut _store;
    (unsafe { (*store).alloc = 0 as i32 as size_t });
    let fresh16 = unsafe { &mut ((*store).storage) };
    *fresh16 = 0 as *mut xmlNodePtr;
    if PUSH_NEXT(
        dst,
        size,
        store,
        minrun,
        run_stack.as_mut_ptr(),
        &mut stack_curr,
        &mut curr,
    ) == 0
    {
        return;
    }
    if PUSH_NEXT(
        dst,
        size,
        store,
        minrun,
        run_stack.as_mut_ptr(),
        &mut stack_curr,
        &mut curr,
    ) == 0
    {
        return;
    }
    if PUSH_NEXT(
        dst,
        size,
        store,
        minrun,
        run_stack.as_mut_ptr(),
        &mut stack_curr,
        &mut curr,
    ) == 0
    {
        return;
    }
    loop {
        if libxml_domnode_check_invariant(run_stack.as_mut_ptr(), stack_curr as i32) == 0 {
            stack_curr = libxml_domnode_tim_sort_collapse(
                dst,
                run_stack.as_mut_ptr(),
                stack_curr as i32,
                store,
                size,
            ) as size_t;
        } else if PUSH_NEXT(
            dst,
            size,
            store,
            minrun,
            run_stack.as_mut_ptr(),
            &mut stack_curr,
            &mut curr,
        ) == 0
        {
            return;
        }
    }
}
extern "C" fn libxml_domnode_tim_sort_collapse(
    mut dst: *mut xmlNodePtr,
    mut stack: *mut TIM_SORT_RUN_T,
    mut stack_curr: i32,
    mut store: *mut TEMP_STORAGE_T,
    size: size_t,
) -> i32 {
    loop {
        let mut A: size_t = 0;
        let mut B: size_t = 0;
        let mut C: size_t = 0;
        let mut D: size_t = 0;
        let mut ABC: i32 = 0;
        let mut BCD: i32 = 0;
        let mut CD: i32 = 0;
        if stack_curr <= 1 as i32 {
            break;
        }
        if stack_curr == 2 as i32
            && (unsafe { (*stack.offset(0 as i32 as isize)).length })
                .wrapping_add(unsafe { (*stack.offset(1 as i32 as isize)).length })
                == size
        {
            libxml_domnode_tim_sort_merge(dst, stack, stack_curr, store);
            let fresh17 = unsafe { &mut ((*stack.offset(0 as i32 as isize)).length) };
            *fresh17 = (*fresh17 as u64).wrapping_add(unsafe { (*stack.offset(1 as i32 as isize)).length })
                as size_t as size_t;
            stack_curr -= 1;
            break;
        } else if stack_curr == 2 as i32
            && (unsafe { (*stack.offset(0 as i32 as isize)).length })
                <= (unsafe { (*stack.offset(1 as i32 as isize)).length })
        {
            libxml_domnode_tim_sort_merge(dst, stack, stack_curr, store);
            let fresh18 = unsafe { &mut ((*stack.offset(0 as i32 as isize)).length) };
            *fresh18 = (*fresh18 as u64).wrapping_add(unsafe { (*stack.offset(1 as i32 as isize)).length })
                as size_t as size_t;
            stack_curr -= 1;
            break;
        } else {
            if stack_curr == 2 as i32 {
                break;
            }
            B = unsafe { (*stack.offset((stack_curr - 3 as i32) as isize)).length };
            C = unsafe { (*stack.offset((stack_curr - 2 as i32) as isize)).length };
            D = unsafe { (*stack.offset((stack_curr - 1 as i32) as isize)).length };
            if stack_curr >= 4 as i32 {
                A = unsafe { (*stack.offset((stack_curr - 4 as i32) as isize)).length };
                ABC = (A <= B.wrapping_add(C)) as i32;
            } else {
                ABC = 0 as i32;
            }
            BCD = (B <= C.wrapping_add(D) || ABC != 0) as i32;
            CD = (C <= D) as i32;
            if BCD == 0 && CD == 0 {
                break;
            }
            if BCD != 0 && CD == 0 {
                libxml_domnode_tim_sort_merge(dst, stack, stack_curr - 1 as i32, store);
                let fresh19 = unsafe { &mut ((*stack.offset((stack_curr - 3 as i32) as isize)).length) };
                *fresh19 = (*fresh19 as u64)
                    .wrapping_add(unsafe { (*stack.offset((stack_curr - 2 as i32) as isize)).length })
                    as size_t as size_t;
                (unsafe { *stack.offset((stack_curr - 2 as i32) as isize) =
                    *stack.offset((stack_curr - 1 as i32) as isize) });
                stack_curr -= 1;
            } else {
                libxml_domnode_tim_sort_merge(dst, stack, stack_curr, store);
                let fresh20 = unsafe { &mut ((*stack.offset((stack_curr - 2 as i32) as isize)).length) };
                *fresh20 = (*fresh20 as u64)
                    .wrapping_add(unsafe { (*stack.offset((stack_curr - 1 as i32) as isize)).length })
                    as size_t as size_t;
                stack_curr -= 1;
            }
        }
    }
    return stack_curr;
}
#[inline]
extern "C" fn PUSH_NEXT(
    mut dst: *mut xmlNodePtr,
    size: size_t,
    mut store: *mut TEMP_STORAGE_T,
    minrun: size_t,
    mut run_stack: *mut TIM_SORT_RUN_T,
    mut stack_curr: *mut size_t,
    mut curr: *mut size_t,
) -> i32 {
    let mut len: size_t = libxml_domnode_count_run(dst, unsafe { *curr }, size);
    let mut run: size_t = minrun;
    if run > size.wrapping_sub(unsafe { *curr }) {
        run = size.wrapping_sub(unsafe { *curr });
    }
    if run > len {
        libxml_domnode_binary_insertion_sort_start(unsafe { &mut *dst.offset(*curr as isize) }, len, run);
        len = run;
    }
    (unsafe { (*run_stack.offset(*stack_curr as isize)).start = *curr });
    (unsafe { (*run_stack.offset(*stack_curr as isize)).length = len });
    (unsafe { *stack_curr = (*stack_curr).wrapping_add(1) });
    (unsafe { *curr = (*curr as u64).wrapping_add(len) as size_t as size_t });
    if (unsafe { *curr }) == size {
        while (unsafe { *stack_curr }) > 1 as i32 as u64 {
            libxml_domnode_tim_sort_merge(dst, run_stack, (unsafe { *stack_curr }) as i32, store);
            let fresh21 = unsafe { &mut ((*run_stack
                .offset((*stack_curr).wrapping_sub(2 as i32 as u64) as isize))
            .length) };
            *fresh21 = (*fresh21 as u64).wrapping_add(
                unsafe { (*run_stack.offset((*stack_curr).wrapping_sub(1 as i32 as u64) as isize)).length },
            ) as size_t as size_t;
            (unsafe { *stack_curr = (*stack_curr).wrapping_sub(1) });
        }
        if !(unsafe { (*store).storage }).is_null() {
            (unsafe { free((*store).storage as *mut libc::c_void) });
            let fresh22 = unsafe { &mut ((*store).storage) };
            *fresh22 = 0 as *mut xmlNodePtr;
        }
        return 0 as i32;
    }
    return 1 as i32;
}
#[no_mangle]
pub static mut xmlXPathNAN: f64 = 0.0f64;
#[no_mangle]
pub static mut xmlXPathPINF: f64 = 0.0f64;
#[no_mangle]
pub static mut xmlXPathNINF: f64 = 0.0f64;
#[no_mangle]
pub extern "C" fn xmlXPathInit() {
    (unsafe { xmlXPathNAN = ::std::f32::NAN as f64 });
    (unsafe { xmlXPathPINF = ::std::f32::INFINITY as f64 });
    (unsafe { xmlXPathNINF = -::std::f32::INFINITY as f64 });
}
#[no_mangle]
pub extern "C" fn xmlXPathIsNaN(mut val: f64) -> i32 {
    return val.is_nan() as i32;
}
#[no_mangle]
pub extern "C" fn xmlXPathIsInf(mut val: f64) -> i32 {
    return if if val.is_infinite() {
        if val.is_sign_positive() {
            1
        } else {
            -1
        }
    } else {
        0
    } != 0
    {
        if val > 0 as i32 as f64 {
            1 as i32
        } else {
            -(1 as i32)
        }
    } else {
        0 as i32
    };
}
static mut xmlXPathXMLNamespaceStruct: xmlNs = {
    let mut init = _xmlNs {
        next: 0 as *const _xmlNs as *mut _xmlNs,
        type_0: XML_NAMESPACE_DECL,
        href: b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
        prefix: b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
        _private: 0 as *const libc::c_void as *mut libc::c_void,
        context: 0 as *const _xmlDoc as *mut _xmlDoc,
    };
    init
};
static mut xmlXPathXMLNamespace: xmlNsPtr =
    unsafe { &xmlXPathXMLNamespaceStruct as *const xmlNs as *mut xmlNs };
static mut xmlXPathErrorMessages: [*const i8; 28] = [
    b"Ok\n\0" as *const u8 as *const i8,
    b"Number encoding\n\0" as *const u8 as *const i8,
    b"Unfinished literal\n\0" as *const u8 as *const i8,
    b"Start of literal\n\0" as *const u8 as *const i8,
    b"Expected $ for variable reference\n\0" as *const u8 as *const i8,
    b"Undefined variable\n\0" as *const u8 as *const i8,
    b"Invalid predicate\n\0" as *const u8 as *const i8,
    b"Invalid expression\n\0" as *const u8 as *const i8,
    b"Missing closing curly brace\n\0" as *const u8 as *const i8,
    b"Unregistered function\n\0" as *const u8 as *const i8,
    b"Invalid operand\n\0" as *const u8 as *const i8,
    b"Invalid type\n\0" as *const u8 as *const i8,
    b"Invalid number of arguments\n\0" as *const u8 as *const i8,
    b"Invalid context size\n\0" as *const u8 as *const i8,
    b"Invalid context position\n\0" as *const u8 as *const i8,
    b"Memory allocation error\n\0" as *const u8 as *const i8,
    b"Syntax error\n\0" as *const u8 as *const i8,
    b"Resource error\n\0" as *const u8 as *const i8,
    b"Sub resource error\n\0" as *const u8 as *const i8,
    b"Undefined namespace prefix\n\0" as *const u8 as *const i8,
    b"Encoding error\n\0" as *const u8 as *const i8,
    b"Char out of XML range\n\0" as *const u8 as *const i8,
    b"Invalid or incomplete context\n\0" as *const u8 as *const i8,
    b"Stack usage error\n\0" as *const u8 as *const i8,
    b"Forbidden variable\n\0" as *const u8 as *const i8,
    b"Operation limit exceeded\n\0" as *const u8 as *const i8,
    b"Recursion limit exceeded\n\0" as *const u8 as *const i8,
    b"?? Unknown error ??\n\0" as *const u8 as *const i8,
];
extern "C" fn xmlXPathErrMemory(mut ctxt: xmlXPathContextPtr, mut extra: *const i8) {
    if !ctxt.is_null() {
        (unsafe { xmlResetError(&mut (*ctxt).lastError) });
        if !extra.is_null() {
            let mut buf: [xmlChar; 200] = [0; 200];
            (unsafe { xmlStrPrintf(
                buf.as_mut_ptr(),
                200 as i32,
                b"Memory allocation failed : %s\n\0" as *const u8 as *const i8,
                extra,
            ) });
            let fresh23 = unsafe { &mut ((*ctxt).lastError.message) };
            *fresh23 = (unsafe { xmlStrdup(buf.as_mut_ptr()) }) as *mut i8;
        } else {
            let fresh24 = unsafe { &mut ((*ctxt).lastError.message) };
            *fresh24 = (unsafe { xmlStrdup(
                b"Memory allocation failed\n\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) as *mut i8;
        }
        (unsafe { (*ctxt).lastError.domain = XML_FROM_XPATH as i32 });
        (unsafe { (*ctxt).lastError.code = XML_ERR_NO_MEMORY as i32 });
        if unsafe { ((*ctxt).error).is_some() } {
            (unsafe { ((*ctxt).error).expect("non-null function pointer")(
                (*ctxt).userData,
                &mut (*ctxt).lastError,
            ) });
        }
    } else if !extra.is_null() {
        (unsafe { __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_XPATH as i32,
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
            XML_FROM_XPATH as i32,
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
extern "C" fn xmlXPathPErrMemory(mut ctxt: xmlXPathParserContextPtr, mut extra: *const i8) {
    if ctxt.is_null() {
        xmlXPathErrMemory(0 as xmlXPathContextPtr, extra);
    } else {
        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
        xmlXPathErrMemory(unsafe { (*ctxt).context }, extra);
    };
}
#[no_mangle]
pub extern "C" fn xmlXPathErr(mut ctxt: xmlXPathParserContextPtr, mut error: i32) {
    if error < 0 as i32
        || error
            > (::std::mem::size_of::<[*const i8; 28]>() as u64)
                .wrapping_div(::std::mem::size_of::<*const i8>() as u64) as i32
                - 1 as i32
    {
        error = (::std::mem::size_of::<[*const i8; 28]>() as u64)
            .wrapping_div(::std::mem::size_of::<*const i8>() as u64) as i32
            - 1 as i32;
    }
    if ctxt.is_null() {
        (unsafe { __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_XPATH as i32,
            error + XML_XPATH_EXPRESSION_OK as i32 - XPATH_EXPRESSION_OK as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            0 as *const i8,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"%s\0" as *const u8 as *const i8,
            xmlXPathErrorMessages[error as usize],
        ) });
        return;
    }
    (unsafe { (*ctxt).error = error });
    if (unsafe { (*ctxt).context }).is_null() {
        (unsafe { __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_XPATH as i32,
            error + XML_XPATH_EXPRESSION_OK as i32 - XPATH_EXPRESSION_OK as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            (*ctxt).base as *const i8,
            0 as *const i8,
            0 as *const i8,
            ((*ctxt).cur).offset_from((*ctxt).base) as i64 as i32,
            0 as i32,
            b"%s\0" as *const u8 as *const i8,
            xmlXPathErrorMessages[error as usize],
        ) });
        return;
    }
    (unsafe { xmlResetError(&mut (*(*ctxt).context).lastError) });
    (unsafe { (*(*ctxt).context).lastError.domain = XML_FROM_XPATH as i32 });
    (unsafe { (*(*ctxt).context).lastError.code =
        error + XML_XPATH_EXPRESSION_OK as i32 - XPATH_EXPRESSION_OK as i32 });
    (unsafe { (*(*ctxt).context).lastError.level = XML_ERR_ERROR });
    let fresh25 = unsafe { &mut ((*(*ctxt).context).lastError.str1) };
    *fresh25 = (unsafe { xmlStrdup((*ctxt).base) }) as *mut i8;
    (unsafe { (*(*ctxt).context).lastError.int1 = ((*ctxt).cur).offset_from((*ctxt).base) as i64 as i32 });
    let fresh26 = unsafe { &mut ((*(*ctxt).context).lastError.node) };
    *fresh26 = (unsafe { (*(*ctxt).context).debugNode }) as *mut libc::c_void;
    if unsafe { ((*(*ctxt).context).error).is_some() } {
        (unsafe { ((*(*ctxt).context).error).expect("non-null function pointer")(
            (*(*ctxt).context).userData,
            &mut (*(*ctxt).context).lastError,
        ) });
    } else {
        (unsafe { __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            (*(*ctxt).context).debugNode as *mut libc::c_void,
            XML_FROM_XPATH as i32,
            error + XML_XPATH_EXPRESSION_OK as i32 - XPATH_EXPRESSION_OK as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            (*ctxt).base as *const i8,
            0 as *const i8,
            0 as *const i8,
            ((*ctxt).cur).offset_from((*ctxt).base) as i64 as i32,
            0 as i32,
            b"%s\0" as *const u8 as *const i8,
            xmlXPathErrorMessages[error as usize],
        ) });
    };
}
#[no_mangle]
pub extern "C" fn xmlXPatherror(
    mut ctxt: xmlXPathParserContextPtr,
    mut _file: *const i8,
    mut _line: i32,
    mut no: i32,
) {
    xmlXPathErr(ctxt, no);
}
extern "C" fn xmlXPathCheckOpLimit(mut ctxt: xmlXPathParserContextPtr, mut opCount: u64) -> i32 {
    let mut xpctxt: xmlXPathContextPtr = unsafe { (*ctxt).context };
    if opCount > (unsafe { (*xpctxt).opLimit }) || (unsafe { (*xpctxt).opCount }) > (unsafe { (*xpctxt).opLimit }).wrapping_sub(opCount)
    {
        (unsafe { (*xpctxt).opCount = (*xpctxt).opLimit });
        xmlXPathErr(ctxt, XPATH_OP_LIMIT_EXCEEDED as i32);
        return -(1 as i32);
    }
    let fresh27 = unsafe { &mut ((*xpctxt).opCount) };
    *fresh27 = (*fresh27).wrapping_add(opCount);
    return 0 as i32;
}
extern "C" fn xmlPointerListAddSize(
    mut list: xmlPointerListPtr,
    mut item: *mut libc::c_void,
    mut initialSize: i32,
) -> i32 {
    if (unsafe { (*list).items }).is_null() {
        if initialSize <= 0 as i32 {
            initialSize = 1 as i32;
        }
        let fresh28 = unsafe { &mut ((*list).items) };
        *fresh28 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            (initialSize as u64).wrapping_mul(::std::mem::size_of::<*mut libc::c_void>() as u64),
        ) }) as *mut *mut libc::c_void;
        if (unsafe { (*list).items }).is_null() {
            xmlXPathErrMemory(
                0 as xmlXPathContextPtr,
                b"xmlPointerListCreate: allocating item\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        (unsafe { (*list).number = 0 as i32 });
        (unsafe { (*list).size = initialSize });
    } else if (unsafe { (*list).size }) <= (unsafe { (*list).number }) {
        if (unsafe { (*list).size }) > 50000000 as i32 {
            xmlXPathErrMemory(
                0 as xmlXPathContextPtr,
                b"xmlPointerListAddSize: re-allocating item\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        (unsafe { (*list).size *= 2 as i32 });
        let fresh29 = unsafe { &mut ((*list).items) };
        *fresh29 = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*list).items as *mut libc::c_void,
            ((*list).size as u64).wrapping_mul(::std::mem::size_of::<*mut libc::c_void>() as u64),
        ) }) as *mut *mut libc::c_void;
        if (unsafe { (*list).items }).is_null() {
            xmlXPathErrMemory(
                0 as xmlXPathContextPtr,
                b"xmlPointerListAddSize: re-allocating item\n\0" as *const u8 as *const i8,
            );
            (unsafe { (*list).size = 0 as i32 });
            return -(1 as i32);
        }
    }
    let fresh30 = unsafe { &mut ((*list).number) };
    let fresh31 = *fresh30;
    *fresh30 = *fresh30 + 1;
    let fresh32 = unsafe { &mut (*((*list).items).offset(fresh31 as isize)) };
    *fresh32 = item;
    return 0 as i32;
}
extern "C" fn xmlPointerListCreate(mut initialSize: i32) -> xmlPointerListPtr {
    let mut ret: xmlPointerListPtr = 0 as *mut xmlPointerList;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlPointerList>() as u64
    ) }) as xmlPointerListPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"xmlPointerListCreate: allocating item\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlPointerListPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlPointerList>() as u64,
    ) });
    if initialSize > 0 as i32 {
        xmlPointerListAddSize(ret, 0 as *mut libc::c_void, initialSize);
        (unsafe { (*ret).number = 0 as i32 });
    }
    return ret;
}
extern "C" fn xmlPointerListFree(mut list: xmlPointerListPtr) {
    if list.is_null() {
        return;
    }
    if !(unsafe { (*list).items }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*list).items as *mut libc::c_void) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(list as *mut libc::c_void) });
}
extern "C" fn xmlXPathNewCompExpr() -> xmlXPathCompExprPtr {
    let mut cur: xmlXPathCompExprPtr = 0 as *mut xmlXPathCompExpr;
    cur = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathCompExpr>() as u64
    ) }) as xmlXPathCompExprPtr;
    if cur.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"allocating component\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathCompExprPtr;
    }
    (unsafe { memset(
        cur as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathCompExpr>() as u64,
    ) });
    (unsafe { (*cur).maxStep = 10 as i32 });
    (unsafe { (*cur).nbStep = 0 as i32 });
    let fresh33 = unsafe { &mut ((*cur).steps) };
    *fresh33 = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ((*cur).maxStep as u64).wrapping_mul(::std::mem::size_of::<xmlXPathStepOp>() as u64),
    ) }) as *mut xmlXPathStepOp;
    if (unsafe { (*cur).steps }).is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"allocating steps\n\0" as *const u8 as *const i8,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
        return 0 as xmlXPathCompExprPtr;
    }
    (unsafe { memset(
        (*cur).steps as *mut libc::c_void,
        0 as i32,
        ((*cur).maxStep as u64).wrapping_mul(::std::mem::size_of::<xmlXPathStepOp>() as u64),
    ) });
    (unsafe { (*cur).last = -(1 as i32) });
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlXPathFreeCompExpr(mut comp: xmlXPathCompExprPtr) {
    let mut op: xmlXPathStepOpPtr = 0 as *mut xmlXPathStepOp;
    let mut i: i32 = 0;
    if comp.is_null() {
        return;
    }
    if (unsafe { (*comp).dict }).is_null() {
        i = 0 as i32;
        while i < (unsafe { (*comp).nbStep }) {
            op = (unsafe { &mut *((*comp).steps).offset(i as isize) }) as *mut xmlXPathStepOp;
            if !(unsafe { (*op).value4 }).is_null() {
                if (unsafe { (*op).op }) as u32 == XPATH_OP_VALUE as i32 as u32 {
                    xmlXPathFreeObject((unsafe { (*op).value4 }) as xmlXPathObjectPtr);
                } else {
                    (unsafe { xmlFree.expect("non-null function pointer")((*op).value4) });
                }
            }
            if !(unsafe { (*op).value5 }).is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")((*op).value5) });
            }
            i += 1;
        }
    } else {
        i = 0 as i32;
        while i < (unsafe { (*comp).nbStep }) {
            op = (unsafe { &mut *((*comp).steps).offset(i as isize) }) as *mut xmlXPathStepOp;
            if !(unsafe { (*op).value4 }).is_null() {
                if (unsafe { (*op).op }) as u32 == XPATH_OP_VALUE as i32 as u32 {
                    xmlXPathFreeObject((unsafe { (*op).value4 }) as xmlXPathObjectPtr);
                }
            }
            i += 1;
        }
        (unsafe { xmlDictFree((*comp).dict) });
    }
    if !(unsafe { (*comp).steps }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*comp).steps as *mut libc::c_void) });
    }
    if !(unsafe { (*comp).stream }).is_null() {
        (unsafe { xmlFreePatternList((*comp).stream) });
    }
    if !(unsafe { (*comp).expr }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*comp).expr as *mut libc::c_void) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(comp as *mut libc::c_void) });
}
extern "C" fn xmlXPathCompExprAdd(
    mut ctxt: xmlXPathParserContextPtr,
    mut ch1: i32,
    mut ch2: i32,
    mut op: xmlXPathOp,
    mut value: i32,
    mut value2: i32,
    mut value3: i32,
    mut value4: *mut libc::c_void,
    mut value5: *mut libc::c_void,
) -> i32 {
    let mut comp: xmlXPathCompExprPtr = unsafe { (*ctxt).comp };
    if (unsafe { (*comp).nbStep }) >= (unsafe { (*comp).maxStep }) {
        let mut real: *mut xmlXPathStepOp = 0 as *mut xmlXPathStepOp;
        if (unsafe { (*comp).maxStep }) >= 1000000 as i32 {
            xmlXPathPErrMemory(ctxt, b"adding step\n\0" as *const u8 as *const i8);
            return -(1 as i32);
        }
        (unsafe { (*comp).maxStep *= 2 as i32 });
        real = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*comp).steps as *mut libc::c_void,
            ((*comp).maxStep as u64).wrapping_mul(::std::mem::size_of::<xmlXPathStepOp>() as u64),
        ) }) as *mut xmlXPathStepOp;
        if real.is_null() {
            (unsafe { (*comp).maxStep /= 2 as i32 });
            xmlXPathPErrMemory(ctxt, b"adding step\n\0" as *const u8 as *const i8);
            return -(1 as i32);
        }
        let fresh34 = unsafe { &mut ((*comp).steps) };
        *fresh34 = real;
    }
    (unsafe { (*comp).last = (*comp).nbStep });
    (unsafe { (*((*comp).steps).offset((*comp).nbStep as isize)).ch1 = ch1 });
    (unsafe { (*((*comp).steps).offset((*comp).nbStep as isize)).ch2 = ch2 });
    (unsafe { (*((*comp).steps).offset((*comp).nbStep as isize)).op = op });
    (unsafe { (*((*comp).steps).offset((*comp).nbStep as isize)).value = value });
    (unsafe { (*((*comp).steps).offset((*comp).nbStep as isize)).value2 = value2 });
    (unsafe { (*((*comp).steps).offset((*comp).nbStep as isize)).value3 = value3 });
    if !(unsafe { (*comp).dict }).is_null()
        && (op as u32 == XPATH_OP_FUNCTION as i32 as u32
            || op as u32 == XPATH_OP_VARIABLE as i32 as u32
            || op as u32 == XPATH_OP_COLLECT as i32 as u32)
    {
        if !value4.is_null() {
            let fresh35 = unsafe { &mut ((*((*comp).steps).offset((*comp).nbStep as isize)).value4) };
            *fresh35 = (unsafe { xmlDictLookup((*comp).dict, value4 as *const xmlChar, -(1 as i32)) })
                as *mut libc::c_void as *mut xmlChar as *mut libc::c_void;
            (unsafe { xmlFree.expect("non-null function pointer")(value4) });
        } else {
            let fresh36 = unsafe { &mut ((*((*comp).steps).offset((*comp).nbStep as isize)).value4) };
            *fresh36 = 0 as *mut libc::c_void;
        }
        if !value5.is_null() {
            let fresh37 = unsafe { &mut ((*((*comp).steps).offset((*comp).nbStep as isize)).value5) };
            *fresh37 = (unsafe { xmlDictLookup((*comp).dict, value5 as *const xmlChar, -(1 as i32)) })
                as *mut libc::c_void as *mut xmlChar as *mut libc::c_void;
            (unsafe { xmlFree.expect("non-null function pointer")(value5) });
        } else {
            let fresh38 = unsafe { &mut ((*((*comp).steps).offset((*comp).nbStep as isize)).value5) };
            *fresh38 = 0 as *mut libc::c_void;
        }
    } else {
        let fresh39 = unsafe { &mut ((*((*comp).steps).offset((*comp).nbStep as isize)).value4) };
        *fresh39 = value4;
        let fresh40 = unsafe { &mut ((*((*comp).steps).offset((*comp).nbStep as isize)).value5) };
        *fresh40 = value5;
    }
    let fresh41 = unsafe { &mut ((*((*comp).steps).offset((*comp).nbStep as isize)).cache) };
    *fresh41 = None;
    let fresh42 = unsafe { &mut ((*comp).nbStep) };
    let fresh43 = *fresh42;
    *fresh42 = *fresh42 + 1;
    return fresh43;
}
extern "C" fn xmlXPathCompSwap(mut op: xmlXPathStepOpPtr) {
    let mut tmp: i32 = 0;
    tmp = unsafe { (*op).ch1 };
    (unsafe { (*op).ch1 = (*op).ch2 });
    (unsafe { (*op).ch2 = tmp });
}
extern "C" fn xmlXPathDebugDumpNode(mut output: *mut FILE, mut cur: xmlNodePtr, mut depth: i32) {
    let mut i: i32 = 0;
    let mut shift: [i8; 100] = [0; 100];
    i = 0 as i32;
    while i < depth && i < 25 as i32 {
        shift[(2 as i32 * i + 1 as i32) as usize] = ' ' as i32 as i8;
        shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
        i += 1;
    }
    shift[(2 as i32 * i + 1 as i32) as usize] = 0 as i32 as i8;
    shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
    if cur.is_null() {
        (unsafe { fprintf(
            output,
            b"%s\0" as *const u8 as *const i8,
            shift.as_mut_ptr(),
        ) });
        (unsafe { fprintf(output, b"Node is NULL !\n\0" as *const u8 as *const i8) });
        return;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
        || (unsafe { (*cur).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        (unsafe { fprintf(
            output,
            b"%s\0" as *const u8 as *const i8,
            shift.as_mut_ptr(),
        ) });
        (unsafe { fprintf(output, b" /\n\0" as *const u8 as *const i8) });
    } else if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
        (unsafe { xmlDebugDumpAttr(output, cur as xmlAttrPtr, depth) });
    } else {
        (unsafe { xmlDebugDumpOneNode(output, cur, depth) });
    };
}
extern "C" fn xmlXPathDebugDumpNodeList(
    mut output: *mut FILE,
    mut cur: xmlNodePtr,
    mut depth: i32,
) {
    let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
    let mut i: i32 = 0;
    let mut shift: [i8; 100] = [0; 100];
    i = 0 as i32;
    while i < depth && i < 25 as i32 {
        shift[(2 as i32 * i + 1 as i32) as usize] = ' ' as i32 as i8;
        shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
        i += 1;
    }
    shift[(2 as i32 * i + 1 as i32) as usize] = 0 as i32 as i8;
    shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
    if cur.is_null() {
        (unsafe { fprintf(
            output,
            b"%s\0" as *const u8 as *const i8,
            shift.as_mut_ptr(),
        ) });
        (unsafe { fprintf(output, b"Node is NULL !\n\0" as *const u8 as *const i8) });
        return;
    }
    while !cur.is_null() {
        tmp = cur;
        cur = unsafe { (*cur).next };
        (unsafe { xmlDebugDumpOneNode(output, tmp, depth) });
    }
}
extern "C" fn xmlXPathDebugDumpNodeSet(
    mut output: *mut FILE,
    mut cur: xmlNodeSetPtr,
    mut depth: i32,
) {
    let mut i: i32 = 0;
    let mut shift: [i8; 100] = [0; 100];
    i = 0 as i32;
    while i < depth && i < 25 as i32 {
        shift[(2 as i32 * i + 1 as i32) as usize] = ' ' as i32 as i8;
        shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
        i += 1;
    }
    shift[(2 as i32 * i + 1 as i32) as usize] = 0 as i32 as i8;
    shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
    if cur.is_null() {
        (unsafe { fprintf(
            output,
            b"%s\0" as *const u8 as *const i8,
            shift.as_mut_ptr(),
        ) });
        (unsafe { fprintf(output, b"NodeSet is NULL !\n\0" as *const u8 as *const i8) });
        return;
    }
    if !cur.is_null() {
        (unsafe { fprintf(
            output,
            b"Set contains %d nodes:\n\0" as *const u8 as *const i8,
            (*cur).nodeNr,
        ) });
        i = 0 as i32;
        while i < (unsafe { (*cur).nodeNr }) {
            (unsafe { fprintf(
                output,
                b"%s\0" as *const u8 as *const i8,
                shift.as_mut_ptr(),
            ) });
            (unsafe { fprintf(output, b"%d\0" as *const u8 as *const i8, i + 1 as i32) });
            xmlXPathDebugDumpNode(
                output,
                unsafe { *((*cur).nodeTab).offset(i as isize) },
                depth + 1 as i32,
            );
            i += 1;
        }
    }
}
extern "C" fn xmlXPathDebugDumpValueTree(
    mut output: *mut FILE,
    mut cur: xmlNodeSetPtr,
    mut depth: i32,
) {
    let mut i: i32 = 0;
    let mut shift: [i8; 100] = [0; 100];
    i = 0 as i32;
    while i < depth && i < 25 as i32 {
        shift[(2 as i32 * i + 1 as i32) as usize] = ' ' as i32 as i8;
        shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
        i += 1;
    }
    shift[(2 as i32 * i + 1 as i32) as usize] = 0 as i32 as i8;
    shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
    if cur.is_null()
        || (unsafe { (*cur).nodeNr }) == 0 as i32
        || (unsafe { *((*cur).nodeTab).offset(0 as i32 as isize) }).is_null()
    {
        (unsafe { fprintf(
            output,
            b"%s\0" as *const u8 as *const i8,
            shift.as_mut_ptr(),
        ) });
        (unsafe { fprintf(
            output,
            b"Value Tree is NULL !\n\0" as *const u8 as *const i8,
        ) });
        return;
    }
    (unsafe { fprintf(
        output,
        b"%s\0" as *const u8 as *const i8,
        shift.as_mut_ptr(),
    ) });
    (unsafe { fprintf(output, b"%d\0" as *const u8 as *const i8, i + 1 as i32) });
    xmlXPathDebugDumpNodeList(
        output,
        unsafe { (**((*cur).nodeTab).offset(0 as i32 as isize)).children },
        depth + 1 as i32,
    );
}
#[no_mangle]
pub extern "C" fn xmlXPathDebugDumpObject(
    mut output: *mut FILE,
    mut cur: xmlXPathObjectPtr,
    mut depth: i32,
) {
    let mut i: i32 = 0;
    let mut shift: [i8; 100] = [0; 100];
    if output.is_null() {
        return;
    }
    i = 0 as i32;
    while i < depth && i < 25 as i32 {
        shift[(2 as i32 * i + 1 as i32) as usize] = ' ' as i32 as i8;
        shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
        i += 1;
    }
    shift[(2 as i32 * i + 1 as i32) as usize] = 0 as i32 as i8;
    shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
    (unsafe { fprintf(
        output,
        b"%s\0" as *const u8 as *const i8,
        shift.as_mut_ptr(),
    ) });
    if cur.is_null() {
        (unsafe { fprintf(
            output,
            b"Object is empty (NULL)\n\0" as *const u8 as *const i8,
        ) });
        return;
    }
    match (unsafe { (*cur).type_0 }) as u32 {
        0 => {
            (unsafe { fprintf(
                output,
                b"Object is uninitialized\n\0" as *const u8 as *const i8,
            ) });
        }
        1 => {
            (unsafe { fprintf(
                output,
                b"Object is a Node Set :\n\0" as *const u8 as *const i8,
            ) });
            xmlXPathDebugDumpNodeSet(output, unsafe { (*cur).nodesetval }, depth);
        }
        9 => {
            (unsafe { fprintf(
                output,
                b"Object is an XSLT value tree :\n\0" as *const u8 as *const i8,
            ) });
            xmlXPathDebugDumpValueTree(output, unsafe { (*cur).nodesetval }, depth);
        }
        2 => {
            (unsafe { fprintf(
                output,
                b"Object is a Boolean : \0" as *const u8 as *const i8,
            ) });
            if (unsafe { (*cur).boolval }) != 0 {
                (unsafe { fprintf(output, b"true\n\0" as *const u8 as *const i8) });
            } else {
                (unsafe { fprintf(output, b"false\n\0" as *const u8 as *const i8) });
            }
        }
        3 => match xmlXPathIsInf(unsafe { (*cur).floatval }) {
            1 => {
                (unsafe { fprintf(
                    output,
                    b"Object is a number : Infinity\n\0" as *const u8 as *const i8,
                ) });
            }
            -1 => {
                (unsafe { fprintf(
                    output,
                    b"Object is a number : -Infinity\n\0" as *const u8 as *const i8,
                ) });
            }
            _ => {
                if xmlXPathIsNaN(unsafe { (*cur).floatval }) != 0 {
                    (unsafe { fprintf(
                        output,
                        b"Object is a number : NaN\n\0" as *const u8 as *const i8,
                    ) });
                } else if (unsafe { (*cur).floatval }) == 0 as i32 as f64 {
                    (unsafe { fprintf(
                        output,
                        b"Object is a number : 0\n\0" as *const u8 as *const i8,
                    ) });
                } else {
                    (unsafe { fprintf(
                        output,
                        b"Object is a number : %0g\n\0" as *const u8 as *const i8,
                        (*cur).floatval,
                    ) });
                }
            }
        },
        4 => {
            (unsafe { fprintf(output, b"Object is a string : \0" as *const u8 as *const i8) });
            (unsafe { xmlDebugDumpString(output, (*cur).stringval) });
            (unsafe { fprintf(output, b"\n\0" as *const u8 as *const i8) });
        }
        8 => {
            (unsafe { fprintf(
                output,
                b"Object is user defined\n\0" as *const u8 as *const i8,
            ) });
        }
        _ => {}
    };
}
extern "C" fn xmlXPathDebugDumpStepOp(
    mut output: *mut FILE,
    mut comp: xmlXPathCompExprPtr,
    mut op: xmlXPathStepOpPtr,
    mut depth: i32,
) {
    let mut current_block: u64;
    let mut i: i32 = 0;
    let mut shift: [i8; 100] = [0; 100];
    i = 0 as i32;
    while i < depth && i < 25 as i32 {
        shift[(2 as i32 * i + 1 as i32) as usize] = ' ' as i32 as i8;
        shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
        i += 1;
    }
    shift[(2 as i32 * i + 1 as i32) as usize] = 0 as i32 as i8;
    shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
    (unsafe { fprintf(
        output,
        b"%s\0" as *const u8 as *const i8,
        shift.as_mut_ptr(),
    ) });
    if op.is_null() {
        (unsafe { fprintf(output, b"Step is NULL\n\0" as *const u8 as *const i8) });
        return;
    }
    match (unsafe { (*op).op }) as u32 {
        0 => {
            (unsafe { fprintf(output, b"END\0" as *const u8 as *const i8) });
            current_block = 12543410360505780601;
        }
        1 => {
            (unsafe { fprintf(output, b"AND\0" as *const u8 as *const i8) });
            current_block = 12543410360505780601;
        }
        2 => {
            (unsafe { fprintf(output, b"OR\0" as *const u8 as *const i8) });
            current_block = 12543410360505780601;
        }
        3 => {
            if (unsafe { (*op).value }) != 0 {
                (unsafe { fprintf(output, b"EQUAL =\0" as *const u8 as *const i8) });
            } else {
                (unsafe { fprintf(output, b"EQUAL !=\0" as *const u8 as *const i8) });
            }
            current_block = 12543410360505780601;
        }
        4 => {
            if (unsafe { (*op).value }) != 0 {
                (unsafe { fprintf(output, b"CMP <\0" as *const u8 as *const i8) });
            } else {
                (unsafe { fprintf(output, b"CMP >\0" as *const u8 as *const i8) });
            }
            if (unsafe { (*op).value2 }) == 0 {
                (unsafe { fprintf(output, b"=\0" as *const u8 as *const i8) });
            }
            current_block = 12543410360505780601;
        }
        5 => {
            if (unsafe { (*op).value }) == 0 as i32 {
                (unsafe { fprintf(output, b"PLUS -\0" as *const u8 as *const i8) });
            } else if (unsafe { (*op).value }) == 1 as i32 {
                (unsafe { fprintf(output, b"PLUS +\0" as *const u8 as *const i8) });
            } else if (unsafe { (*op).value }) == 2 as i32 {
                (unsafe { fprintf(output, b"PLUS unary -\0" as *const u8 as *const i8) });
            } else if (unsafe { (*op).value }) == 3 as i32 {
                (unsafe { fprintf(output, b"PLUS unary - -\0" as *const u8 as *const i8) });
            }
            current_block = 12543410360505780601;
        }
        6 => {
            if (unsafe { (*op).value }) == 0 as i32 {
                (unsafe { fprintf(output, b"MULT *\0" as *const u8 as *const i8) });
            } else if (unsafe { (*op).value }) == 1 as i32 {
                (unsafe { fprintf(output, b"MULT div\0" as *const u8 as *const i8) });
            } else {
                (unsafe { fprintf(output, b"MULT mod\0" as *const u8 as *const i8) });
            }
            current_block = 12543410360505780601;
        }
        7 => {
            (unsafe { fprintf(output, b"UNION\0" as *const u8 as *const i8) });
            current_block = 12543410360505780601;
        }
        8 => {
            (unsafe { fprintf(output, b"ROOT\0" as *const u8 as *const i8) });
            current_block = 12543410360505780601;
        }
        9 => {
            (unsafe { fprintf(output, b"NODE\0" as *const u8 as *const i8) });
            current_block = 12543410360505780601;
        }
        17 => {
            (unsafe { fprintf(output, b"SORT\0" as *const u8 as *const i8) });
            current_block = 12543410360505780601;
        }
        10 => {
            let mut axis: xmlXPathAxisVal = (unsafe { (*op).value }) as xmlXPathAxisVal;
            let mut test: xmlXPathTestVal = (unsafe { (*op).value2 }) as xmlXPathTestVal;
            let mut type_0: xmlXPathTypeVal = (unsafe { (*op).value3 }) as xmlXPathTypeVal;
            let mut prefix: *const xmlChar = (unsafe { (*op).value4 }) as *const xmlChar;
            let mut name: *const xmlChar = (unsafe { (*op).value5 }) as *const xmlChar;
            (unsafe { fprintf(output, b"COLLECT \0" as *const u8 as *const i8) });
            match axis as u32 {
                1 => {
                    (unsafe { fprintf(output, b" 'ancestors' \0" as *const u8 as *const i8) });
                }
                2 => {
                    (unsafe { fprintf(output, b" 'ancestors-or-self' \0" as *const u8 as *const i8) });
                }
                3 => {
                    (unsafe { fprintf(output, b" 'attributes' \0" as *const u8 as *const i8) });
                }
                4 => {
                    (unsafe { fprintf(output, b" 'child' \0" as *const u8 as *const i8) });
                }
                5 => {
                    (unsafe { fprintf(output, b" 'descendant' \0" as *const u8 as *const i8) });
                }
                6 => {
                    (unsafe { fprintf(
                        output,
                        b" 'descendant-or-self' \0" as *const u8 as *const i8,
                    ) });
                }
                7 => {
                    (unsafe { fprintf(output, b" 'following' \0" as *const u8 as *const i8) });
                }
                8 => {
                    (unsafe { fprintf(
                        output,
                        b" 'following-siblings' \0" as *const u8 as *const i8,
                    ) });
                }
                9 => {
                    (unsafe { fprintf(output, b" 'namespace' \0" as *const u8 as *const i8) });
                }
                10 => {
                    (unsafe { fprintf(output, b" 'parent' \0" as *const u8 as *const i8) });
                }
                11 => {
                    (unsafe { fprintf(output, b" 'preceding' \0" as *const u8 as *const i8) });
                }
                12 => {
                    (unsafe { fprintf(output, b" 'preceding-sibling' \0" as *const u8 as *const i8) });
                }
                13 => {
                    (unsafe { fprintf(output, b" 'self' \0" as *const u8 as *const i8) });
                }
                _ => {}
            }
            match test as u32 {
                0 => {
                    (unsafe { fprintf(output, b"'none' \0" as *const u8 as *const i8) });
                }
                1 => {
                    (unsafe { fprintf(output, b"'type' \0" as *const u8 as *const i8) });
                }
                2 => {
                    (unsafe { fprintf(output, b"'PI' \0" as *const u8 as *const i8) });
                }
                3 => {
                    (unsafe { fprintf(output, b"'all' \0" as *const u8 as *const i8) });
                }
                4 => {
                    (unsafe { fprintf(output, b"'namespace' \0" as *const u8 as *const i8) });
                }
                5 => {
                    (unsafe { fprintf(output, b"'name' \0" as *const u8 as *const i8) });
                }
                _ => {}
            }
            match type_0 as u32 {
                0 => {
                    (unsafe { fprintf(output, b"'node' \0" as *const u8 as *const i8) });
                }
                8 => {
                    (unsafe { fprintf(output, b"'comment' \0" as *const u8 as *const i8) });
                }
                3 => {
                    (unsafe { fprintf(output, b"'text' \0" as *const u8 as *const i8) });
                }
                7 => {
                    (unsafe { fprintf(output, b"'PI' \0" as *const u8 as *const i8) });
                }
                _ => {}
            }
            if !prefix.is_null() {
                (unsafe { fprintf(output, b"%s:\0" as *const u8 as *const i8, prefix) });
            }
            if !name.is_null() {
                (unsafe { fprintf(output, b"%s\0" as *const u8 as *const i8, name as *const i8) });
            }
            current_block = 12543410360505780601;
        }
        11 => {
            let mut object: xmlXPathObjectPtr = (unsafe { (*op).value4 }) as xmlXPathObjectPtr;
            (unsafe { fprintf(output, b"ELEM \0" as *const u8 as *const i8) });
            xmlXPathDebugDumpObject(output, object, 0 as i32);
            current_block = 17901564827269852576;
        }
        12 => {
            let mut prefix_0: *const xmlChar = (unsafe { (*op).value5 }) as *const xmlChar;
            let mut name_0: *const xmlChar = (unsafe { (*op).value4 }) as *const xmlChar;
            if !prefix_0.is_null() {
                (unsafe { fprintf(
                    output,
                    b"VARIABLE %s:%s\0" as *const u8 as *const i8,
                    prefix_0,
                    name_0,
                ) });
            } else {
                (unsafe { fprintf(output, b"VARIABLE %s\0" as *const u8 as *const i8, name_0) });
            }
            current_block = 12543410360505780601;
        }
        13 => {
            let mut nbargs: i32 = unsafe { (*op).value };
            let mut prefix_1: *const xmlChar = (unsafe { (*op).value5 }) as *const xmlChar;
            let mut name_1: *const xmlChar = (unsafe { (*op).value4 }) as *const xmlChar;
            if !prefix_1.is_null() {
                (unsafe { fprintf(
                    output,
                    b"FUNCTION %s:%s(%d args)\0" as *const u8 as *const i8,
                    prefix_1,
                    name_1,
                    nbargs,
                ) });
            } else {
                (unsafe { fprintf(
                    output,
                    b"FUNCTION %s(%d args)\0" as *const u8 as *const i8,
                    name_1,
                    nbargs,
                ) });
            }
            current_block = 12543410360505780601;
        }
        14 => {
            (unsafe { fprintf(output, b"ARG\0" as *const u8 as *const i8) });
            current_block = 12543410360505780601;
        }
        15 => {
            (unsafe { fprintf(output, b"PREDICATE\0" as *const u8 as *const i8) });
            current_block = 12543410360505780601;
        }
        16 => {
            (unsafe { fprintf(output, b"FILTER\0" as *const u8 as *const i8) });
            current_block = 12543410360505780601;
        }
        _ => {
            (unsafe { fprintf(
                output,
                b"UNKNOWN %d\n\0" as *const u8 as *const i8,
                (*op).op as u32,
            ) });
            return;
        }
    }
    match current_block {
        12543410360505780601 => {
            (unsafe { fprintf(output, b"\n\0" as *const u8 as *const i8) });
        }
        _ => {}
    }
    if (unsafe { (*op).ch1 }) >= 0 as i32 {
        xmlXPathDebugDumpStepOp(
            output,
            comp,
            unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) },
            depth + 1 as i32,
        );
    }
    if (unsafe { (*op).ch2 }) >= 0 as i32 {
        xmlXPathDebugDumpStepOp(
            output,
            comp,
            unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) },
            depth + 1 as i32,
        );
    }
}
#[no_mangle]
pub extern "C" fn xmlXPathDebugDumpCompExpr(
    mut output: *mut FILE,
    mut comp: xmlXPathCompExprPtr,
    mut depth: i32,
) {
    let mut i: i32 = 0;
    let mut shift: [i8; 100] = [0; 100];
    if output.is_null() || comp.is_null() {
        return;
    }
    i = 0 as i32;
    while i < depth && i < 25 as i32 {
        shift[(2 as i32 * i + 1 as i32) as usize] = ' ' as i32 as i8;
        shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
        i += 1;
    }
    shift[(2 as i32 * i + 1 as i32) as usize] = 0 as i32 as i8;
    shift[(2 as i32 * i) as usize] = shift[(2 as i32 * i + 1 as i32) as usize];
    (unsafe { fprintf(
        output,
        b"%s\0" as *const u8 as *const i8,
        shift.as_mut_ptr(),
    ) });
    if !(unsafe { (*comp).stream }).is_null() {
        (unsafe { fprintf(
            output,
            b"Streaming Expression\n\0" as *const u8 as *const i8,
        ) });
    } else {
        (unsafe { fprintf(
            output,
            b"Compiled Expression : %d elements\n\0" as *const u8 as *const i8,
            (*comp).nbStep,
        ) });
        i = unsafe { (*comp).last };
        xmlXPathDebugDumpStepOp(
            output,
            comp,
            unsafe { &mut *((*comp).steps).offset(i as isize) },
            depth + 1 as i32,
        );
    };
}
extern "C" fn xmlXPathNewCache() -> xmlXPathContextCachePtr {
    let mut ret: xmlXPathContextCachePtr = 0 as *mut xmlXPathContextCache;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathContextCache>() as u64,
    ) }) as xmlXPathContextCachePtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"creating object cache\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathContextCachePtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathContextCache>() as u64,
    ) });
    (unsafe { (*ret).maxNodeset = 100 as i32 });
    (unsafe { (*ret).maxString = 100 as i32 });
    (unsafe { (*ret).maxBoolean = 100 as i32 });
    (unsafe { (*ret).maxNumber = 100 as i32 });
    (unsafe { (*ret).maxMisc = 100 as i32 });
    return ret;
}
extern "C" fn xmlXPathCacheFreeObjectList(mut list: xmlPointerListPtr) {
    let mut i: i32 = 0;
    let mut obj: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if list.is_null() {
        return;
    }
    i = 0 as i32;
    while i < (unsafe { (*list).number }) {
        obj = (unsafe { *((*list).items).offset(i as isize) }) as xmlXPathObjectPtr;
        if !(unsafe { (*obj).nodesetval }).is_null() {
            if !(unsafe { (*(*obj).nodesetval).nodeTab }).is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(
                    (*(*obj).nodesetval).nodeTab as *mut libc::c_void,
                ) });
            }
            (unsafe { xmlFree.expect("non-null function pointer")((*obj).nodesetval as *mut libc::c_void) });
        }
        (unsafe { xmlFree.expect("non-null function pointer")(obj as *mut libc::c_void) });
        i += 1;
    }
    xmlPointerListFree(list);
}
extern "C" fn xmlXPathFreeCache(mut cache: xmlXPathContextCachePtr) {
    if cache.is_null() {
        return;
    }
    if !(unsafe { (*cache).nodesetObjs }).is_null() {
        xmlXPathCacheFreeObjectList(unsafe { (*cache).nodesetObjs });
    }
    if !(unsafe { (*cache).stringObjs }).is_null() {
        xmlXPathCacheFreeObjectList(unsafe { (*cache).stringObjs });
    }
    if !(unsafe { (*cache).booleanObjs }).is_null() {
        xmlXPathCacheFreeObjectList(unsafe { (*cache).booleanObjs });
    }
    if !(unsafe { (*cache).numberObjs }).is_null() {
        xmlXPathCacheFreeObjectList(unsafe { (*cache).numberObjs });
    }
    if !(unsafe { (*cache).miscObjs }).is_null() {
        xmlXPathCacheFreeObjectList(unsafe { (*cache).miscObjs });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(cache as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlXPathContextSetCache(
    mut ctxt: xmlXPathContextPtr,
    mut active: i32,
    mut value: i32,
    mut options: i32,
) -> i32 {
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if active != 0 {
        let mut cache: xmlXPathContextCachePtr = 0 as *mut xmlXPathContextCache;
        if (unsafe { (*ctxt).cache }).is_null() {
            let fresh44 = unsafe { &mut ((*ctxt).cache) };
            *fresh44 = xmlXPathNewCache() as *mut libc::c_void;
            if (unsafe { (*ctxt).cache }).is_null() {
                return -(1 as i32);
            }
        }
        cache = (unsafe { (*ctxt).cache }) as xmlXPathContextCachePtr;
        if options == 0 as i32 {
            if value < 0 as i32 {
                value = 100 as i32;
            }
            (unsafe { (*cache).maxNodeset = value });
            (unsafe { (*cache).maxString = value });
            (unsafe { (*cache).maxNumber = value });
            (unsafe { (*cache).maxBoolean = value });
            (unsafe { (*cache).maxMisc = value });
        }
    } else if !(unsafe { (*ctxt).cache }).is_null() {
        xmlXPathFreeCache((unsafe { (*ctxt).cache }) as xmlXPathContextCachePtr);
        let fresh45 = unsafe { &mut ((*ctxt).cache) };
        *fresh45 = 0 as *mut libc::c_void;
    }
    return 0 as i32;
}
extern "C" fn xmlXPathCacheWrapNodeSet(
    mut ctxt: xmlXPathContextPtr,
    mut val: xmlNodeSetPtr,
) -> xmlXPathObjectPtr {
    if !ctxt.is_null() && !(unsafe { (*ctxt).cache }).is_null() {
        let mut cache: xmlXPathContextCachePtr = (unsafe { (*ctxt).cache }) as xmlXPathContextCachePtr;
        if !(unsafe { (*cache).miscObjs }).is_null() && (unsafe { (*(*cache).miscObjs).number }) != 0 as i32 {
            let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
            let fresh46 = unsafe { &mut ((*(*cache).miscObjs).number) };
            *fresh46 -= 1;
            ret = (unsafe { *((*(*cache).miscObjs).items).offset(*fresh46 as isize) }) as xmlXPathObjectPtr;
            (unsafe { (*ret).type_0 = XPATH_NODESET });
            let fresh47 = unsafe { &mut ((*ret).nodesetval) };
            *fresh47 = val;
            return ret;
        }
    }
    return xmlXPathWrapNodeSet(val);
}
extern "C" fn xmlXPathCacheWrapString(
    mut ctxt: xmlXPathContextPtr,
    mut val: *mut xmlChar,
) -> xmlXPathObjectPtr {
    if !ctxt.is_null() && !(unsafe { (*ctxt).cache }).is_null() {
        let mut cache: xmlXPathContextCachePtr = (unsafe { (*ctxt).cache }) as xmlXPathContextCachePtr;
        if !(unsafe { (*cache).stringObjs }).is_null() && (unsafe { (*(*cache).stringObjs).number }) != 0 as i32 {
            let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
            let fresh48 = unsafe { &mut ((*(*cache).stringObjs).number) };
            *fresh48 -= 1;
            ret = (unsafe { *((*(*cache).stringObjs).items).offset(*fresh48 as isize) }) as xmlXPathObjectPtr;
            (unsafe { (*ret).type_0 = XPATH_STRING });
            let fresh49 = unsafe { &mut ((*ret).stringval) };
            *fresh49 = val;
            return ret;
        } else {
            if !(unsafe { (*cache).miscObjs }).is_null() && (unsafe { (*(*cache).miscObjs).number }) != 0 as i32 {
                let mut ret_0: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
                let fresh50 = unsafe { &mut ((*(*cache).miscObjs).number) };
                *fresh50 -= 1;
                ret_0 =
                    (unsafe { *((*(*cache).miscObjs).items).offset(*fresh50 as isize) }) as xmlXPathObjectPtr;
                (unsafe { (*ret_0).type_0 = XPATH_STRING });
                let fresh51 = unsafe { &mut ((*ret_0).stringval) };
                *fresh51 = val;
                return ret_0;
            }
        }
    }
    return xmlXPathWrapString(val);
}
extern "C" fn xmlXPathCacheNewNodeSet(
    mut ctxt: xmlXPathContextPtr,
    mut val: xmlNodePtr,
) -> xmlXPathObjectPtr {
    if !ctxt.is_null() && !(unsafe { (*ctxt).cache }).is_null() {
        let mut cache: xmlXPathContextCachePtr = (unsafe { (*ctxt).cache }) as xmlXPathContextCachePtr;
        if !(unsafe { (*cache).nodesetObjs }).is_null() && (unsafe { (*(*cache).nodesetObjs).number }) != 0 as i32 {
            let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
            let fresh52 = unsafe { &mut ((*(*cache).nodesetObjs).number) };
            *fresh52 -= 1;
            ret = (unsafe { *((*(*cache).nodesetObjs).items).offset(*fresh52 as isize) }) as xmlXPathObjectPtr;
            (unsafe { (*ret).type_0 = XPATH_NODESET });
            (unsafe { (*ret).boolval = 0 as i32 });
            if !val.is_null() {
                if (unsafe { (*(*ret).nodesetval).nodeMax }) == 0 as i32
                    || (unsafe { (*val).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
                {
                    xmlXPathNodeSetAddUnique(unsafe { (*ret).nodesetval }, val);
                } else {
                    let fresh53 = unsafe { &mut (*((*(*ret).nodesetval).nodeTab).offset(0 as i32 as isize)) };
                    *fresh53 = val;
                    (unsafe { (*(*ret).nodesetval).nodeNr = 1 as i32 });
                }
            }
            return ret;
        } else {
            if !(unsafe { (*cache).miscObjs }).is_null() && (unsafe { (*(*cache).miscObjs).number }) != 0 as i32 {
                let mut ret_0: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
                let fresh54 = unsafe { &mut ((*(*cache).miscObjs).number) };
                *fresh54 -= 1;
                ret_0 =
                    (unsafe { *((*(*cache).miscObjs).items).offset(*fresh54 as isize) }) as xmlXPathObjectPtr;
                (unsafe { (*ret_0).type_0 = XPATH_NODESET });
                (unsafe { (*ret_0).boolval = 0 as i32 });
                let fresh55 = unsafe { &mut ((*ret_0).nodesetval) };
                *fresh55 = xmlXPathNodeSetCreate(val);
                if (unsafe { (*ret_0).nodesetval }).is_null() {
                    (unsafe { (*ctxt).lastError.domain = XML_FROM_XPATH as i32 });
                    (unsafe { (*ctxt).lastError.code = XML_ERR_NO_MEMORY as i32 });
                    return 0 as xmlXPathObjectPtr;
                }
                return ret_0;
            }
        }
    }
    return xmlXPathNewNodeSet(val);
}
extern "C" fn xmlXPathCacheNewCString(
    mut ctxt: xmlXPathContextPtr,
    mut val: *const i8,
) -> xmlXPathObjectPtr {
    if !ctxt.is_null() && !(unsafe { (*ctxt).cache }).is_null() {
        let mut cache: xmlXPathContextCachePtr = (unsafe { (*ctxt).cache }) as xmlXPathContextCachePtr;
        if !(unsafe { (*cache).stringObjs }).is_null() && (unsafe { (*(*cache).stringObjs).number }) != 0 as i32 {
            let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
            let fresh56 = unsafe { &mut ((*(*cache).stringObjs).number) };
            *fresh56 -= 1;
            ret = (unsafe { *((*(*cache).stringObjs).items).offset(*fresh56 as isize) }) as xmlXPathObjectPtr;
            (unsafe { (*ret).type_0 = XPATH_STRING });
            let fresh57 = unsafe { &mut ((*ret).stringval) };
            *fresh57 = unsafe { xmlStrdup(val as *mut xmlChar) };
            return ret;
        } else {
            if !(unsafe { (*cache).miscObjs }).is_null() && (unsafe { (*(*cache).miscObjs).number }) != 0 as i32 {
                let mut ret_0: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
                let fresh58 = unsafe { &mut ((*(*cache).miscObjs).number) };
                *fresh58 -= 1;
                ret_0 =
                    (unsafe { *((*(*cache).miscObjs).items).offset(*fresh58 as isize) }) as xmlXPathObjectPtr;
                (unsafe { (*ret_0).type_0 = XPATH_STRING });
                let fresh59 = unsafe { &mut ((*ret_0).stringval) };
                *fresh59 = unsafe { xmlStrdup(val as *mut xmlChar) };
                return ret_0;
            }
        }
    }
    return xmlXPathNewCString(val);
}
extern "C" fn xmlXPathCacheNewString(
    mut ctxt: xmlXPathContextPtr,
    mut val: *const xmlChar,
) -> xmlXPathObjectPtr {
    if !ctxt.is_null() && !(unsafe { (*ctxt).cache }).is_null() {
        let mut cache: xmlXPathContextCachePtr = (unsafe { (*ctxt).cache }) as xmlXPathContextCachePtr;
        if !(unsafe { (*cache).stringObjs }).is_null() && (unsafe { (*(*cache).stringObjs).number }) != 0 as i32 {
            let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
            let fresh60 = unsafe { &mut ((*(*cache).stringObjs).number) };
            *fresh60 -= 1;
            ret = (unsafe { *((*(*cache).stringObjs).items).offset(*fresh60 as isize) }) as xmlXPathObjectPtr;
            (unsafe { (*ret).type_0 = XPATH_STRING });
            if !val.is_null() {
                let fresh61 = unsafe { &mut ((*ret).stringval) };
                *fresh61 = unsafe { xmlStrdup(val) };
            } else {
                let fresh62 = unsafe { &mut ((*ret).stringval) };
                *fresh62 = unsafe { xmlStrdup(b"\0" as *const u8 as *const i8 as *const xmlChar) };
            }
            return ret;
        } else {
            if !(unsafe { (*cache).miscObjs }).is_null() && (unsafe { (*(*cache).miscObjs).number }) != 0 as i32 {
                let mut ret_0: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
                let fresh63 = unsafe { &mut ((*(*cache).miscObjs).number) };
                *fresh63 -= 1;
                ret_0 =
                    (unsafe { *((*(*cache).miscObjs).items).offset(*fresh63 as isize) }) as xmlXPathObjectPtr;
                (unsafe { (*ret_0).type_0 = XPATH_STRING });
                if !val.is_null() {
                    let fresh64 = unsafe { &mut ((*ret_0).stringval) };
                    *fresh64 = unsafe { xmlStrdup(val) };
                } else {
                    let fresh65 = unsafe { &mut ((*ret_0).stringval) };
                    *fresh65 = unsafe { xmlStrdup(b"\0" as *const u8 as *const i8 as *const xmlChar) };
                }
                return ret_0;
            }
        }
    }
    return xmlXPathNewString(val);
}
extern "C" fn xmlXPathCacheNewBoolean(
    mut ctxt: xmlXPathContextPtr,
    mut val: i32,
) -> xmlXPathObjectPtr {
    if !ctxt.is_null() && !(unsafe { (*ctxt).cache }).is_null() {
        let mut cache: xmlXPathContextCachePtr = (unsafe { (*ctxt).cache }) as xmlXPathContextCachePtr;
        if !(unsafe { (*cache).booleanObjs }).is_null() && (unsafe { (*(*cache).booleanObjs).number }) != 0 as i32 {
            let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
            let fresh66 = unsafe { &mut ((*(*cache).booleanObjs).number) };
            *fresh66 -= 1;
            ret = (unsafe { *((*(*cache).booleanObjs).items).offset(*fresh66 as isize) }) as xmlXPathObjectPtr;
            (unsafe { (*ret).type_0 = XPATH_BOOLEAN });
            (unsafe { (*ret).boolval = (val != 0 as i32) as i32 });
            return ret;
        } else {
            if !(unsafe { (*cache).miscObjs }).is_null() && (unsafe { (*(*cache).miscObjs).number }) != 0 as i32 {
                let mut ret_0: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
                let fresh67 = unsafe { &mut ((*(*cache).miscObjs).number) };
                *fresh67 -= 1;
                ret_0 =
                    (unsafe { *((*(*cache).miscObjs).items).offset(*fresh67 as isize) }) as xmlXPathObjectPtr;
                (unsafe { (*ret_0).type_0 = XPATH_BOOLEAN });
                (unsafe { (*ret_0).boolval = (val != 0 as i32) as i32 });
                return ret_0;
            }
        }
    }
    return xmlXPathNewBoolean(val);
}
extern "C" fn xmlXPathCacheNewFloat(
    mut ctxt: xmlXPathContextPtr,
    mut val: f64,
) -> xmlXPathObjectPtr {
    if !ctxt.is_null() && !(unsafe { (*ctxt).cache }).is_null() {
        let mut cache: xmlXPathContextCachePtr = (unsafe { (*ctxt).cache }) as xmlXPathContextCachePtr;
        if !(unsafe { (*cache).numberObjs }).is_null() && (unsafe { (*(*cache).numberObjs).number }) != 0 as i32 {
            let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
            let fresh68 = unsafe { &mut ((*(*cache).numberObjs).number) };
            *fresh68 -= 1;
            ret = (unsafe { *((*(*cache).numberObjs).items).offset(*fresh68 as isize) }) as xmlXPathObjectPtr;
            (unsafe { (*ret).type_0 = XPATH_NUMBER });
            (unsafe { (*ret).floatval = val });
            return ret;
        } else {
            if !(unsafe { (*cache).miscObjs }).is_null() && (unsafe { (*(*cache).miscObjs).number }) != 0 as i32 {
                let mut ret_0: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
                let fresh69 = unsafe { &mut ((*(*cache).miscObjs).number) };
                *fresh69 -= 1;
                ret_0 =
                    (unsafe { *((*(*cache).miscObjs).items).offset(*fresh69 as isize) }) as xmlXPathObjectPtr;
                (unsafe { (*ret_0).type_0 = XPATH_NUMBER });
                (unsafe { (*ret_0).floatval = val });
                return ret_0;
            }
        }
    }
    return xmlXPathNewFloat(val);
}
extern "C" fn xmlXPathCacheConvertString(
    mut ctxt: xmlXPathContextPtr,
    mut val: xmlXPathObjectPtr,
) -> xmlXPathObjectPtr {
    let mut res: *mut xmlChar = 0 as *mut xmlChar;
    if val.is_null() {
        return xmlXPathCacheNewCString(ctxt, b"\0" as *const u8 as *const i8);
    }
    match (unsafe { (*val).type_0 }) as u32 {
        1 | 9 => {
            res = xmlXPathCastNodeSetToString(unsafe { (*val).nodesetval });
        }
        4 => return val,
        2 => {
            res = xmlXPathCastBooleanToString(unsafe { (*val).boolval });
        }
        3 => {
            res = xmlXPathCastNumberToString(unsafe { (*val).floatval });
        }
        8 => {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                b"xpath.c\0" as *const u8 as *const i8,
                2718 as i32,
            ) });
        }
        0 | _ => {}
    }
    xmlXPathReleaseObject(ctxt, val);
    if res.is_null() {
        return xmlXPathCacheNewCString(ctxt, b"\0" as *const u8 as *const i8);
    }
    return xmlXPathCacheWrapString(ctxt, res);
}
extern "C" fn xmlXPathCacheObjectCopy(
    mut ctxt: xmlXPathContextPtr,
    mut val: xmlXPathObjectPtr,
) -> xmlXPathObjectPtr {
    if val.is_null() {
        return 0 as xmlXPathObjectPtr;
    }
    if !ctxt.is_null() && !(unsafe { (*ctxt).cache }).is_null() {
        match (unsafe { (*val).type_0 }) as u32 {
            1 => {
                return xmlXPathCacheWrapNodeSet(
                    ctxt,
                    xmlXPathNodeSetMerge(0 as xmlNodeSetPtr, unsafe { (*val).nodesetval }),
                );
            }
            4 => return xmlXPathCacheNewString(ctxt, unsafe { (*val).stringval }),
            2 => return xmlXPathCacheNewBoolean(ctxt, unsafe { (*val).boolval }),
            3 => return xmlXPathCacheNewFloat(ctxt, unsafe { (*val).floatval }),
            _ => {}
        }
    }
    return xmlXPathObjectCopy(val);
}
extern "C" fn xmlXPathCacheConvertBoolean(
    mut ctxt: xmlXPathContextPtr,
    mut val: xmlXPathObjectPtr,
) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if val.is_null() {
        return xmlXPathCacheNewBoolean(ctxt, 0 as i32);
    }
    if (unsafe { (*val).type_0 }) as u32 == XPATH_BOOLEAN as i32 as u32 {
        return val;
    }
    ret = xmlXPathCacheNewBoolean(ctxt, xmlXPathCastToBoolean(val));
    xmlXPathReleaseObject(ctxt, val);
    return ret;
}
extern "C" fn xmlXPathCacheConvertNumber(
    mut ctxt: xmlXPathContextPtr,
    mut val: xmlXPathObjectPtr,
) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if val.is_null() {
        return xmlXPathCacheNewFloat(ctxt, 0.0f64);
    }
    if (unsafe { (*val).type_0 }) as u32 == XPATH_NUMBER as i32 as u32 {
        return val;
    }
    ret = xmlXPathCacheNewFloat(ctxt, xmlXPathCastToNumber(val));
    xmlXPathReleaseObject(ctxt, val);
    return ret;
}
extern "C" fn xmlXPathSetFrame(mut ctxt: xmlXPathParserContextPtr) -> i32 {
    let mut ret: i32 = 0;
    if ctxt.is_null() {
        return 0 as i32;
    }
    ret = unsafe { (*ctxt).valueFrame };
    (unsafe { (*ctxt).valueFrame = (*ctxt).valueNr });
    return ret;
}
extern "C" fn xmlXPathPopFrame(mut ctxt: xmlXPathParserContextPtr, mut frame: i32) {
    if ctxt.is_null() {
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) {
        xmlXPatherror(
            ctxt,
            b"xpath.c\0" as *const u8 as *const i8,
            2846 as i32,
            XPATH_STACK_ERROR as i32,
        );
    }
    (unsafe { (*ctxt).valueFrame = frame });
}
#[no_mangle]
pub extern "C" fn valuePop(mut ctxt: xmlXPathParserContextPtr) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if ctxt.is_null() || (unsafe { (*ctxt).valueNr }) <= 0 as i32 {
        return 0 as xmlXPathObjectPtr;
    }
    if (unsafe { (*ctxt).valueNr }) <= (unsafe { (*ctxt).valueFrame }) {
        xmlXPatherror(
            ctxt,
            b"xpath.c\0" as *const u8 as *const i8,
            2868 as i32,
            XPATH_STACK_ERROR as i32,
        );
        return 0 as xmlXPathObjectPtr;
    }
    let fresh70 = unsafe { &mut ((*ctxt).valueNr) };
    *fresh70 -= 1;
    if (unsafe { (*ctxt).valueNr }) > 0 as i32 {
        let fresh71 = unsafe { &mut ((*ctxt).value) };
        *fresh71 = unsafe { *((*ctxt).valueTab).offset(((*ctxt).valueNr - 1 as i32) as isize) };
    } else {
        let fresh72 = unsafe { &mut ((*ctxt).value) };
        *fresh72 = 0 as xmlXPathObjectPtr;
    }
    ret = unsafe { *((*ctxt).valueTab).offset((*ctxt).valueNr as isize) };
    let fresh73 = unsafe { &mut (*((*ctxt).valueTab).offset((*ctxt).valueNr as isize)) };
    *fresh73 = 0 as xmlXPathObjectPtr;
    return ret;
}
#[no_mangle]
pub extern "C" fn valuePush(
    mut ctxt: xmlXPathParserContextPtr,
    mut value: xmlXPathObjectPtr,
) -> i32 {
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if value.is_null() {
        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).valueNr }) >= (unsafe { (*ctxt).valueMax }) {
        let mut tmp: *mut xmlXPathObjectPtr = 0 as *mut xmlXPathObjectPtr;
        if (unsafe { (*ctxt).valueMax }) >= 1000000 as i32 {
            xmlXPathPErrMemory(
                ctxt,
                b"XPath stack depth limit reached\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*ctxt).valueTab as *mut libc::c_void,
            ((2 as i32 * (*ctxt).valueMax) as u64)
                .wrapping_mul(::std::mem::size_of::<xmlXPathObjectPtr>() as u64),
        ) }) as *mut xmlXPathObjectPtr;
        if tmp.is_null() {
            xmlXPathPErrMemory(ctxt, b"pushing value\n\0" as *const u8 as *const i8);
            return -(1 as i32);
        }
        (unsafe { (*ctxt).valueMax *= 2 as i32 });
        let fresh74 = unsafe { &mut ((*ctxt).valueTab) };
        *fresh74 = tmp;
    }
    let fresh75 = unsafe { &mut (*((*ctxt).valueTab).offset((*ctxt).valueNr as isize)) };
    *fresh75 = value;
    let fresh76 = unsafe { &mut ((*ctxt).value) };
    *fresh76 = value;
    let fresh77 = unsafe { &mut ((*ctxt).valueNr) };
    let fresh78 = *fresh77;
    *fresh77 = *fresh77 + 1;
    return fresh78;
}
#[no_mangle]
pub extern "C" fn xmlXPathPopBoolean(mut ctxt: xmlXPathParserContextPtr) -> i32 {
    let mut obj: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut ret: i32 = 0;
    obj = valuePop(ctxt);
    if obj.is_null() {
        xmlXPatherror(
            ctxt,
            b"xpath.c\0" as *const u8 as *const i8,
            2941 as i32,
            XPATH_INVALID_OPERAND as i32,
        );
        if !ctxt.is_null() {
            (unsafe { (*ctxt).error = XPATH_INVALID_OPERAND as i32 });
        }
        return 0 as i32;
    }
    if (unsafe { (*obj).type_0 }) as u32 != XPATH_BOOLEAN as i32 as u32 {
        ret = xmlXPathCastToBoolean(obj);
    } else {
        ret = unsafe { (*obj).boolval };
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, obj);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathPopNumber(mut ctxt: xmlXPathParserContextPtr) -> f64 {
    let mut obj: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut ret: f64 = 0.;
    obj = valuePop(ctxt);
    if obj.is_null() {
        xmlXPatherror(
            ctxt,
            b"xpath.c\0" as *const u8 as *const i8,
            2968 as i32,
            XPATH_INVALID_OPERAND as i32,
        );
        if !ctxt.is_null() {
            (unsafe { (*ctxt).error = XPATH_INVALID_OPERAND as i32 });
        }
        return 0 as i32 as f64;
    }
    if (unsafe { (*obj).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        ret = xmlXPathCastToNumber(obj);
    } else {
        ret = unsafe { (*obj).floatval };
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, obj);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathPopString(mut ctxt: xmlXPathParserContextPtr) -> *mut xmlChar {
    let mut obj: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    obj = valuePop(ctxt);
    if obj.is_null() {
        xmlXPatherror(
            ctxt,
            b"xpath.c\0" as *const u8 as *const i8,
            2995 as i32,
            XPATH_INVALID_OPERAND as i32,
        );
        if !ctxt.is_null() {
            (unsafe { (*ctxt).error = XPATH_INVALID_OPERAND as i32 });
        }
        return 0 as *mut xmlChar;
    }
    ret = xmlXPathCastToString(obj);
    if (unsafe { (*obj).stringval }) == ret {
        let fresh79 = unsafe { &mut ((*obj).stringval) };
        *fresh79 = 0 as *mut xmlChar;
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, obj);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathPopNodeSet(mut ctxt: xmlXPathParserContextPtr) -> xmlNodeSetPtr {
    let mut obj: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut ret: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    if ctxt.is_null() {
        return 0 as xmlNodeSetPtr;
    }
    if (unsafe { (*ctxt).value }).is_null() {
        xmlXPatherror(
            ctxt,
            b"xpath.c\0" as *const u8 as *const i8,
            3022 as i32,
            XPATH_INVALID_OPERAND as i32,
        );
        if !ctxt.is_null() {
            (unsafe { (*ctxt).error = XPATH_INVALID_OPERAND as i32 });
        }
        return 0 as xmlNodeSetPtr;
    }
    if !(!(unsafe { (*ctxt).value }).is_null()
        && ((unsafe { (*(*ctxt).value).type_0 }) as u32 == XPATH_NODESET as i32 as u32
            || (unsafe { (*(*ctxt).value).type_0 }) as u32 == XPATH_XSLT_TREE as i32 as u32))
    {
        xmlXPatherror(
            ctxt,
            b"xpath.c\0" as *const u8 as *const i8,
            3026 as i32,
            XPATH_INVALID_TYPE as i32,
        );
        if !ctxt.is_null() {
            (unsafe { (*ctxt).error = XPATH_INVALID_TYPE as i32 });
        }
        return 0 as xmlNodeSetPtr;
    }
    obj = valuePop(ctxt);
    ret = unsafe { (*obj).nodesetval };
    let fresh80 = unsafe { &mut ((*obj).nodesetval) };
    *fresh80 = 0 as xmlNodeSetPtr;
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, obj);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathPopExternal(mut ctxt: xmlXPathParserContextPtr) -> *mut libc::c_void {
    let mut obj: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut ret: *mut libc::c_void = 0 as *mut libc::c_void;
    if ctxt.is_null() || (unsafe { (*ctxt).value }).is_null() {
        xmlXPatherror(
            ctxt,
            b"xpath.c\0" as *const u8 as *const i8,
            3056 as i32,
            XPATH_INVALID_OPERAND as i32,
        );
        if !ctxt.is_null() {
            (unsafe { (*ctxt).error = XPATH_INVALID_OPERAND as i32 });
        }
        return 0 as *mut libc::c_void;
    }
    if (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_USERS as i32 as u32 {
        xmlXPatherror(
            ctxt,
            b"xpath.c\0" as *const u8 as *const i8,
            3060 as i32,
            XPATH_INVALID_TYPE as i32,
        );
        if !ctxt.is_null() {
            (unsafe { (*ctxt).error = XPATH_INVALID_TYPE as i32 });
        }
        return 0 as *mut libc::c_void;
    }
    obj = valuePop(ctxt);
    ret = unsafe { (*obj).user };
    let fresh81 = unsafe { &mut ((*obj).user) };
    *fresh81 = 0 as *mut libc::c_void;
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, obj);
    return ret;
}
extern "C" fn xmlXPathFormatNumber(mut number: f64, mut buffer: *mut i8, mut buffersize: i32) {
    match xmlXPathIsInf(number) {
        1 => {
            if buffersize > ::std::mem::size_of::<[i8; 9]>() as u64 as i32 {
                (unsafe { snprintf(
                    buffer,
                    buffersize as u64,
                    b"Infinity\0" as *const u8 as *const i8,
                ) });
            }
        }
        -1 => {
            if buffersize > ::std::mem::size_of::<[i8; 10]>() as u64 as i32 {
                (unsafe { snprintf(
                    buffer,
                    buffersize as u64,
                    b"-Infinity\0" as *const u8 as *const i8,
                ) });
            }
        }
        _ => {
            if xmlXPathIsNaN(number) != 0 {
                if buffersize > ::std::mem::size_of::<[i8; 4]>() as u64 as i32 {
                    (unsafe { snprintf(
                        buffer,
                        buffersize as u64,
                        b"NaN\0" as *const u8 as *const i8,
                    ) });
                }
            } else if number == 0 as i32 as f64 {
                (unsafe { snprintf(buffer, buffersize as u64, b"0\0" as *const u8 as *const i8) });
            } else if number > (-(2147483647 as i32) - 1 as i32) as f64
                && number < 2147483647 as i32 as f64
                && number == number as i32 as f64
            {
                let mut work: [i8; 30] = [0; 30];
                let mut ptr: *mut i8 = 0 as *mut i8;
                let mut cur: *mut i8 = 0 as *mut i8;
                let mut value: i32 = number as i32;
                ptr = (unsafe { &mut *buffer.offset(0 as i32 as isize) }) as *mut i8;
                if value == 0 as i32 {
                    let fresh82 = ptr;
                    ptr = unsafe { ptr.offset(1) };
                    (unsafe { *fresh82 = '0' as i32 as i8 });
                } else {
                    (unsafe { snprintf(
                        work.as_mut_ptr(),
                        29 as i32 as u64,
                        b"%d\0" as *const u8 as *const i8,
                        value,
                    ) });
                    cur = (unsafe { &mut *work.as_mut_ptr().offset(0 as i32 as isize) }) as *mut i8;
                    while (unsafe { *cur }) as i32 != 0 && ((unsafe { ptr.offset_from(buffer) }) as i64) < buffersize as i64 {
                        let fresh83 = cur;
                        cur = unsafe { cur.offset(1) };
                        let fresh84 = ptr;
                        ptr = unsafe { ptr.offset(1) };
                        (unsafe { *fresh84 = *fresh83 });
                    }
                }
                if ((unsafe { ptr.offset_from(buffer) }) as i64) < buffersize as i64 {
                    (unsafe { *ptr = 0 as i32 as i8 });
                } else if buffersize > 0 as i32 {
                    ptr = unsafe { ptr.offset(-1) };
                    (unsafe { *ptr = 0 as i32 as i8 });
                }
            } else {
                let mut work_0: [i8; 28] = [0; 28];
                let mut integer_place: i32 = 0;
                let mut fraction_place: i32 = 0;
                let mut ptr_0: *mut i8 = 0 as *mut i8;
                let mut after_fraction: *mut i8 = 0 as *mut i8;
                let mut absolute_value: f64 = 0.;
                let mut size: i32 = 0;
                absolute_value = unsafe { fabs(number) };
                if (absolute_value > 1E9f64 || absolute_value < 1E-5f64) && absolute_value != 0.0f64
                {
                    integer_place = 15 as i32 + (3 as i32 + 2 as i32) + 1 as i32;
                    fraction_place = 15 as i32 - 1 as i32;
                    size = unsafe { snprintf(
                        work_0.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 28]>() as u64,
                        b"%*.*e\0" as *const u8 as *const i8,
                        integer_place,
                        fraction_place,
                        number,
                    ) };
                    while size > 0 as i32 && work_0[size as usize] as i32 != 'e' as i32 {
                        size -= 1;
                    }
                } else {
                    if absolute_value > 0.0f64 {
                        integer_place = (unsafe { log10(absolute_value) }) as i32;
                        if integer_place > 0 as i32 {
                            fraction_place = 15 as i32 - integer_place - 1 as i32;
                        } else {
                            fraction_place = 15 as i32 - integer_place;
                        }
                    } else {
                        fraction_place = 1 as i32;
                    }
                    size = unsafe { snprintf(
                        work_0.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 28]>() as u64,
                        b"%0.*f\0" as *const u8 as *const i8,
                        fraction_place,
                        number,
                    ) };
                }
                while work_0[0 as i32 as usize] as i32 == ' ' as i32 {
                    ptr_0 = (unsafe { &mut *work_0.as_mut_ptr().offset(0 as i32 as isize) }) as *mut i8;
                    loop {
                        let fresh85 = unsafe { &mut (*ptr_0.offset(0 as i32 as isize)) };
                        *fresh85 = unsafe { *ptr_0.offset(1 as i32 as isize) };
                        if !(*fresh85 != 0) {
                            break;
                        }
                        ptr_0 = unsafe { ptr_0.offset(1) };
                    }
                    size -= 1;
                }
                after_fraction = unsafe { work_0.as_mut_ptr().offset(size as isize) };
                ptr_0 = after_fraction;
                loop {
                    ptr_0 = unsafe { ptr_0.offset(-1) };
                    if !((unsafe { *ptr_0 }) as i32 == '0' as i32) {
                        break;
                    }
                }
                if (unsafe { *ptr_0 }) as i32 != '.' as i32 {
                    ptr_0 = unsafe { ptr_0.offset(1) };
                }
                loop {
                    let fresh86 = after_fraction;
                    after_fraction = unsafe { after_fraction.offset(1) };
                    let fresh87 = ptr_0;
                    ptr_0 = unsafe { ptr_0.offset(1) };
                    (unsafe { *fresh87 = *fresh86 });
                    if !((unsafe { *fresh87 }) as i32 != 0 as i32) {
                        break;
                    }
                }
                size = (unsafe { strlen(work_0.as_mut_ptr()) }).wrapping_add(1 as i32 as u64) as i32;
                if size > buffersize {
                    work_0[(buffersize - 1 as i32) as usize] = 0 as i32 as i8;
                    size = buffersize;
                }
                (unsafe { memmove(
                    buffer as *mut libc::c_void,
                    work_0.as_mut_ptr() as *const libc::c_void,
                    size as u64,
                ) });
            }
        }
    };
}
#[no_mangle]
pub extern "C" fn xmlXPathOrderDocElems(mut doc: xmlDocPtr) -> i64 {
    let mut count: ptrdiff_t = 0 as i32 as ptrdiff_t;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if doc.is_null() {
        return -(1 as i32) as i64;
    }
    cur = unsafe { (*doc).children };
    while !cur.is_null() {
        if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            count += 1;
            let fresh88 = unsafe { &mut ((*cur).content) };
            *fresh88 = -count as *mut libc::c_void as *mut xmlChar;
            if !(unsafe { (*cur).children }).is_null() {
                cur = unsafe { (*cur).children };
                continue;
            }
        }
        if !(unsafe { (*cur).next }).is_null() {
            cur = unsafe { (*cur).next };
        } else {
            loop {
                cur = unsafe { (*cur).parent };
                if cur.is_null() {
                    break;
                }
                if cur == doc as xmlNodePtr {
                    cur = 0 as xmlNodePtr;
                    break;
                } else if !(unsafe { (*cur).next }).is_null() {
                    cur = unsafe { (*cur).next };
                    break;
                } else if cur.is_null() {
                    break;
                }
            }
        }
    }
    return count;
}
#[no_mangle]
pub extern "C" fn xmlXPathCmpNodes(mut node1: xmlNodePtr, mut node2: xmlNodePtr) -> i32 {
    let mut depth1: i32 = 0;
    let mut depth2: i32 = 0;
    let mut attr1: i32 = 0 as i32;
    let mut attr2: i32 = 0 as i32;
    let mut attrNode1: xmlNodePtr = 0 as xmlNodePtr;
    let mut attrNode2: xmlNodePtr = 0 as xmlNodePtr;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut root: xmlNodePtr = 0 as *mut xmlNode;
    if node1.is_null() || node2.is_null() {
        return -(2 as i32);
    }
    if node1 == node2 {
        return 0 as i32;
    }
    if (unsafe { (*node1).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
        attr1 = 1 as i32;
        attrNode1 = node1;
        node1 = unsafe { (*node1).parent };
    }
    if (unsafe { (*node2).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
        attr2 = 1 as i32;
        attrNode2 = node2;
        node2 = unsafe { (*node2).parent };
    }
    if node1 == node2 {
        if attr1 == attr2 {
            if attr1 != 0 as i32 {
                cur = unsafe { (*attrNode2).prev };
                while !cur.is_null() {
                    if cur == attrNode1 {
                        return 1 as i32;
                    }
                    cur = unsafe { (*cur).prev };
                }
                return -(1 as i32);
            }
            return 0 as i32;
        }
        if attr2 == 1 as i32 {
            return 1 as i32;
        }
        return -(1 as i32);
    }
    if (unsafe { (*node1).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
        || (unsafe { (*node2).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
    {
        return 1 as i32;
    }
    if node1 == (unsafe { (*node2).prev }) {
        return 1 as i32;
    }
    if node1 == (unsafe { (*node2).next }) {
        return -(1 as i32);
    }
    if (unsafe { (*node1).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
        && (unsafe { (*node2).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
        && 0 as i32 as i64 > (unsafe { (*node1).content }) as ptrdiff_t
        && 0 as i32 as i64 > (unsafe { (*node2).content }) as ptrdiff_t
        && (unsafe { (*node1).doc }) == (unsafe { (*node2).doc })
    {
        let mut l1: ptrdiff_t = 0;
        let mut l2: ptrdiff_t = 0;
        l1 = -((unsafe { (*node1).content }) as ptrdiff_t);
        l2 = -((unsafe { (*node2).content }) as ptrdiff_t);
        if l1 < l2 {
            return 1 as i32;
        }
        if l1 > l2 {
            return -(1 as i32);
        }
    }
    depth2 = 0 as i32;
    cur = node2;
    while !(unsafe { (*cur).parent }).is_null() {
        if (unsafe { (*cur).parent }) == node1 {
            return 1 as i32;
        }
        depth2 += 1;
        cur = unsafe { (*cur).parent };
    }
    root = cur;
    depth1 = 0 as i32;
    cur = node1;
    while !(unsafe { (*cur).parent }).is_null() {
        if (unsafe { (*cur).parent }) == node2 {
            return -(1 as i32);
        }
        depth1 += 1;
        cur = unsafe { (*cur).parent };
    }
    if root != cur {
        return -(2 as i32);
    }
    while depth1 > depth2 {
        depth1 -= 1;
        node1 = unsafe { (*node1).parent };
    }
    while depth2 > depth1 {
        depth2 -= 1;
        node2 = unsafe { (*node2).parent };
    }
    while (unsafe { (*node1).parent }) != (unsafe { (*node2).parent }) {
        node1 = unsafe { (*node1).parent };
        node2 = unsafe { (*node2).parent };
        if node1.is_null() || node2.is_null() {
            return -(2 as i32);
        }
    }
    if node1 == (unsafe { (*node2).prev }) {
        return 1 as i32;
    }
    if node1 == (unsafe { (*node2).next }) {
        return -(1 as i32);
    }
    if (unsafe { (*node1).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
        && (unsafe { (*node2).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
        && 0 as i32 as i64 > (unsafe { (*node1).content }) as ptrdiff_t
        && 0 as i32 as i64 > (unsafe { (*node2).content }) as ptrdiff_t
        && (unsafe { (*node1).doc }) == (unsafe { (*node2).doc })
    {
        let mut l1_0: ptrdiff_t = 0;
        let mut l2_0: ptrdiff_t = 0;
        l1_0 = -((unsafe { (*node1).content }) as ptrdiff_t);
        l2_0 = -((unsafe { (*node2).content }) as ptrdiff_t);
        if l1_0 < l2_0 {
            return 1 as i32;
        }
        if l1_0 > l2_0 {
            return -(1 as i32);
        }
    }
    cur = unsafe { (*node1).next };
    while !cur.is_null() {
        if cur == node2 {
            return 1 as i32;
        }
        cur = unsafe { (*cur).next };
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeSetSort(mut set: xmlNodeSetPtr) {
    if set.is_null() {
        return;
    }
    libxml_domnode_tim_sort(unsafe { (*set).nodeTab }, (unsafe { (*set).nodeNr }) as size_t);
}
extern "C" fn xmlXPathNodeSetDupNs(mut node: xmlNodePtr, mut ns: xmlNsPtr) -> xmlNodePtr {
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    if ns.is_null() || (unsafe { (*ns).type_0 }) as u32 != XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if node.is_null() || (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return ns as xmlNodePtr;
    }
    cur = (unsafe { xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNs>() as u64) })
        as xmlNsPtr;
    if cur.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"duplicating namespace\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlNodePtr;
    }
    (unsafe { memset(
        cur as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlNs>() as u64,
    ) });
    (unsafe { (*cur).type_0 = XML_NAMESPACE_DECL });
    if !(unsafe { (*ns).href }).is_null() {
        let fresh89 = unsafe { &mut ((*cur).href) };
        *fresh89 = unsafe { xmlStrdup((*ns).href) };
    }
    if !(unsafe { (*ns).prefix }).is_null() {
        let fresh90 = unsafe { &mut ((*cur).prefix) };
        *fresh90 = unsafe { xmlStrdup((*ns).prefix) };
    }
    let fresh91 = unsafe { &mut ((*cur).next) };
    *fresh91 = node as xmlNsPtr;
    return cur as xmlNodePtr;
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeSetFreeNs(mut ns: xmlNsPtr) {
    if ns.is_null() || (unsafe { (*ns).type_0 }) as u32 != XML_NAMESPACE_DECL as i32 as u32 {
        return;
    }
    if !(unsafe { (*ns).next }).is_null() && (unsafe { (*(*ns).next).type_0 }) as u32 != XML_NAMESPACE_DECL as i32 as u32 {
        if !(unsafe { (*ns).href }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(
                (*ns).href as *mut xmlChar as *mut libc::c_void,
            ) });
        }
        if !(unsafe { (*ns).prefix }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(
                (*ns).prefix as *mut xmlChar as *mut libc::c_void,
            ) });
        }
        (unsafe { xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void) });
    }
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeSetCreate(mut val: xmlNodePtr) -> xmlNodeSetPtr {
    let mut ret: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNodeSet>() as u64) })
        as xmlNodeSetPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"creating nodeset\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlNodeSetPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlNodeSet>() as u64,
    ) });
    if !val.is_null() {
        let fresh92 = unsafe { &mut ((*ret).nodeTab) };
        *fresh92 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) }) as *mut xmlNodePtr;
        if (unsafe { (*ret).nodeTab }).is_null() {
            xmlXPathErrMemory(
                0 as xmlXPathContextPtr,
                b"creating nodeset\n\0" as *const u8 as *const i8,
            );
            (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
            return 0 as xmlNodeSetPtr;
        }
        (unsafe { memset(
            (*ret).nodeTab as *mut libc::c_void,
            0 as i32,
            (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) });
        (unsafe { (*ret).nodeMax = 10 as i32 });
        if (unsafe { (*val).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
            let mut ns: xmlNsPtr = val as xmlNsPtr;
            let fresh93 = unsafe { &mut ((*ret).nodeNr) };
            let fresh94 = *fresh93;
            *fresh93 = *fresh93 + 1;
            let fresh95 = unsafe { &mut (*((*ret).nodeTab).offset(fresh94 as isize)) };
            *fresh95 = xmlXPathNodeSetDupNs((unsafe { (*ns).next }) as xmlNodePtr, ns);
        } else {
            let fresh96 = unsafe { &mut ((*ret).nodeNr) };
            let fresh97 = *fresh96;
            *fresh96 = *fresh96 + 1;
            let fresh98 = unsafe { &mut (*((*ret).nodeTab).offset(fresh97 as isize)) };
            *fresh98 = val;
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeSetContains(mut cur: xmlNodeSetPtr, mut val: xmlNodePtr) -> i32 {
    let mut i: i32 = 0;
    if cur.is_null() || val.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*val).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        i = 0 as i32;
        while i < (unsafe { (*cur).nodeNr }) {
            if (unsafe { (**((*cur).nodeTab).offset(i as isize)).type_0 }) as u32
                == XML_NAMESPACE_DECL as i32 as u32
            {
                let mut ns1: xmlNsPtr = 0 as *mut xmlNs;
                let mut ns2: xmlNsPtr = 0 as *mut xmlNs;
                ns1 = val as xmlNsPtr;
                ns2 = (unsafe { *((*cur).nodeTab).offset(i as isize) }) as xmlNsPtr;
                if ns1 == ns2 {
                    return 1 as i32;
                }
                if !(unsafe { (*ns1).next }).is_null()
                    && (unsafe { (*ns2).next }) == (unsafe { (*ns1).next })
                    && (unsafe { xmlStrEqual((*ns1).prefix, (*ns2).prefix) }) != 0
                {
                    return 1 as i32;
                }
            }
            i += 1;
        }
    } else {
        i = 0 as i32;
        while i < (unsafe { (*cur).nodeNr }) {
            if (unsafe { *((*cur).nodeTab).offset(i as isize) }) == val {
                return 1 as i32;
            }
            i += 1;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeSetAddNs(
    mut cur: xmlNodeSetPtr,
    mut node: xmlNodePtr,
    mut ns: xmlNsPtr,
) -> i32 {
    let mut i: i32 = 0;
    if cur.is_null()
        || ns.is_null()
        || node.is_null()
        || (unsafe { (*ns).type_0 }) as u32 != XML_NAMESPACE_DECL as i32 as u32
        || (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
    {
        return -(1 as i32);
    }
    i = 0 as i32;
    while i < (unsafe { (*cur).nodeNr }) {
        if !(unsafe { *((*cur).nodeTab).offset(i as isize) }).is_null()
            && (unsafe { (**((*cur).nodeTab).offset(i as isize)).type_0 }) as u32
                == XML_NAMESPACE_DECL as i32 as u32
            && (unsafe { (*(*((*cur).nodeTab).offset(i as isize) as xmlNsPtr)).next }) == node as xmlNsPtr
            && (unsafe { xmlStrEqual(
                (*ns).prefix,
                (*(*((*cur).nodeTab).offset(i as isize) as xmlNsPtr)).prefix,
            ) }) != 0
        {
            return 0 as i32;
        }
        i += 1;
    }
    if (unsafe { (*cur).nodeMax }) == 0 as i32 {
        let fresh99 = unsafe { &mut ((*cur).nodeTab) };
        *fresh99 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) }) as *mut xmlNodePtr;
        if (unsafe { (*cur).nodeTab }).is_null() {
            xmlXPathErrMemory(
                0 as xmlXPathContextPtr,
                b"growing nodeset\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        (unsafe { memset(
            (*cur).nodeTab as *mut libc::c_void,
            0 as i32,
            (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) });
        (unsafe { (*cur).nodeMax = 10 as i32 });
    } else if (unsafe { (*cur).nodeNr }) == (unsafe { (*cur).nodeMax }) {
        let mut temp: *mut xmlNodePtr = 0 as *mut xmlNodePtr;
        if (unsafe { (*cur).nodeMax }) >= 10000000 as i32 {
            xmlXPathErrMemory(
                0 as xmlXPathContextPtr,
                b"growing nodeset hit limit\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        temp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*cur).nodeTab as *mut libc::c_void,
            (((*cur).nodeMax * 2 as i32) as u64)
                .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) }) as *mut xmlNodePtr;
        if temp.is_null() {
            xmlXPathErrMemory(
                0 as xmlXPathContextPtr,
                b"growing nodeset\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        (unsafe { (*cur).nodeMax *= 2 as i32 });
        let fresh100 = unsafe { &mut ((*cur).nodeTab) };
        *fresh100 = temp;
    }
    let fresh101 = unsafe { &mut ((*cur).nodeNr) };
    let fresh102 = *fresh101;
    *fresh101 = *fresh101 + 1;
    let fresh103 = unsafe { &mut (*((*cur).nodeTab).offset(fresh102 as isize)) };
    *fresh103 = xmlXPathNodeSetDupNs(node, ns);
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeSetAdd(mut cur: xmlNodeSetPtr, mut val: xmlNodePtr) -> i32 {
    let mut i: i32 = 0;
    if cur.is_null() || val.is_null() {
        return -(1 as i32);
    }
    i = 0 as i32;
    while i < (unsafe { (*cur).nodeNr }) {
        if (unsafe { *((*cur).nodeTab).offset(i as isize) }) == val {
            return 0 as i32;
        }
        i += 1;
    }
    if (unsafe { (*cur).nodeMax }) == 0 as i32 {
        let fresh104 = unsafe { &mut ((*cur).nodeTab) };
        *fresh104 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) }) as *mut xmlNodePtr;
        if (unsafe { (*cur).nodeTab }).is_null() {
            xmlXPathErrMemory(
                0 as xmlXPathContextPtr,
                b"growing nodeset\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        (unsafe { memset(
            (*cur).nodeTab as *mut libc::c_void,
            0 as i32,
            (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) });
        (unsafe { (*cur).nodeMax = 10 as i32 });
    } else if (unsafe { (*cur).nodeNr }) == (unsafe { (*cur).nodeMax }) {
        let mut temp: *mut xmlNodePtr = 0 as *mut xmlNodePtr;
        if (unsafe { (*cur).nodeMax }) >= 10000000 as i32 {
            xmlXPathErrMemory(
                0 as xmlXPathContextPtr,
                b"growing nodeset hit limit\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        temp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*cur).nodeTab as *mut libc::c_void,
            (((*cur).nodeMax * 2 as i32) as u64)
                .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) }) as *mut xmlNodePtr;
        if temp.is_null() {
            xmlXPathErrMemory(
                0 as xmlXPathContextPtr,
                b"growing nodeset\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        (unsafe { (*cur).nodeMax *= 2 as i32 });
        let fresh105 = unsafe { &mut ((*cur).nodeTab) };
        *fresh105 = temp;
    }
    if (unsafe { (*val).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        let mut ns: xmlNsPtr = val as xmlNsPtr;
        let fresh106 = unsafe { &mut ((*cur).nodeNr) };
        let fresh107 = *fresh106;
        *fresh106 = *fresh106 + 1;
        let fresh108 = unsafe { &mut (*((*cur).nodeTab).offset(fresh107 as isize)) };
        *fresh108 = xmlXPathNodeSetDupNs((unsafe { (*ns).next }) as xmlNodePtr, ns);
    } else {
        let fresh109 = unsafe { &mut ((*cur).nodeNr) };
        let fresh110 = *fresh109;
        *fresh109 = *fresh109 + 1;
        let fresh111 = unsafe { &mut (*((*cur).nodeTab).offset(fresh110 as isize)) };
        *fresh111 = val;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeSetAddUnique(mut cur: xmlNodeSetPtr, mut val: xmlNodePtr) -> i32 {
    if cur.is_null() || val.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*cur).nodeMax }) == 0 as i32 {
        let fresh112 = unsafe { &mut ((*cur).nodeTab) };
        *fresh112 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) }) as *mut xmlNodePtr;
        if (unsafe { (*cur).nodeTab }).is_null() {
            xmlXPathErrMemory(
                0 as xmlXPathContextPtr,
                b"growing nodeset\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        (unsafe { memset(
            (*cur).nodeTab as *mut libc::c_void,
            0 as i32,
            (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) });
        (unsafe { (*cur).nodeMax = 10 as i32 });
    } else if (unsafe { (*cur).nodeNr }) == (unsafe { (*cur).nodeMax }) {
        let mut temp: *mut xmlNodePtr = 0 as *mut xmlNodePtr;
        if (unsafe { (*cur).nodeMax }) >= 10000000 as i32 {
            xmlXPathErrMemory(
                0 as xmlXPathContextPtr,
                b"growing nodeset hit limit\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        temp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*cur).nodeTab as *mut libc::c_void,
            (((*cur).nodeMax * 2 as i32) as u64)
                .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) }) as *mut xmlNodePtr;
        if temp.is_null() {
            xmlXPathErrMemory(
                0 as xmlXPathContextPtr,
                b"growing nodeset\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        let fresh113 = unsafe { &mut ((*cur).nodeTab) };
        *fresh113 = temp;
        (unsafe { (*cur).nodeMax *= 2 as i32 });
    }
    if (unsafe { (*val).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        let mut ns: xmlNsPtr = val as xmlNsPtr;
        let fresh114 = unsafe { &mut ((*cur).nodeNr) };
        let fresh115 = *fresh114;
        *fresh114 = *fresh114 + 1;
        let fresh116 = unsafe { &mut (*((*cur).nodeTab).offset(fresh115 as isize)) };
        *fresh116 = xmlXPathNodeSetDupNs((unsafe { (*ns).next }) as xmlNodePtr, ns);
    } else {
        let fresh117 = unsafe { &mut ((*cur).nodeNr) };
        let fresh118 = *fresh117;
        *fresh117 = *fresh117 + 1;
        let fresh119 = unsafe { &mut (*((*cur).nodeTab).offset(fresh118 as isize)) };
        *fresh119 = val;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeSetMerge(
    mut val1: xmlNodeSetPtr,
    mut val2: xmlNodeSetPtr,
) -> xmlNodeSetPtr {
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    let mut initNr: i32 = 0;
    let mut skip: i32 = 0;
    let mut n1: xmlNodePtr = 0 as *mut xmlNode;
    let mut n2: xmlNodePtr = 0 as *mut xmlNode;
    if val2.is_null() {
        return val1;
    }
    if val1.is_null() {
        val1 = xmlXPathNodeSetCreate(0 as xmlNodePtr);
        if val1.is_null() {
            return 0 as xmlNodeSetPtr;
        }
    }
    initNr = unsafe { (*val1).nodeNr };
    i = 0 as i32;
    while i < (unsafe { (*val2).nodeNr }) {
        n2 = unsafe { *((*val2).nodeTab).offset(i as isize) };
        skip = 0 as i32;
        j = 0 as i32;
        while j < initNr {
            n1 = unsafe { *((*val1).nodeTab).offset(j as isize) };
            if n1 == n2 {
                skip = 1 as i32;
                break;
            } else {
                if (unsafe { (*n1).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
                    && (unsafe { (*n2).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
                {
                    if (unsafe { (*(n1 as xmlNsPtr)).next }) == (unsafe { (*(n2 as xmlNsPtr)).next })
                        && (unsafe { xmlStrEqual((*(n1 as xmlNsPtr)).prefix, (*(n2 as xmlNsPtr)).prefix) }) != 0
                    {
                        skip = 1 as i32;
                        break;
                    }
                }
                j += 1;
            }
        }
        if !(skip != 0) {
            if (unsafe { (*val1).nodeMax }) == 0 as i32 {
                let fresh120 = unsafe { &mut ((*val1).nodeTab) };
                *fresh120 = (unsafe { xmlMalloc.expect("non-null function pointer")(
                    (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
                ) }) as *mut xmlNodePtr;
                if (unsafe { (*val1).nodeTab }).is_null() {
                    xmlXPathErrMemory(
                        0 as xmlXPathContextPtr,
                        b"merging nodeset\n\0" as *const u8 as *const i8,
                    );
                    return 0 as xmlNodeSetPtr;
                }
                (unsafe { memset(
                    (*val1).nodeTab as *mut libc::c_void,
                    0 as i32,
                    (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
                ) });
                (unsafe { (*val1).nodeMax = 10 as i32 });
            } else if (unsafe { (*val1).nodeNr }) == (unsafe { (*val1).nodeMax }) {
                let mut temp: *mut xmlNodePtr = 0 as *mut xmlNodePtr;
                if (unsafe { (*val1).nodeMax }) >= 10000000 as i32 {
                    xmlXPathErrMemory(
                        0 as xmlXPathContextPtr,
                        b"merging nodeset hit limit\n\0" as *const u8 as *const i8,
                    );
                    return 0 as xmlNodeSetPtr;
                }
                temp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                    (*val1).nodeTab as *mut libc::c_void,
                    (((*val1).nodeMax * 2 as i32) as u64)
                        .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
                ) }) as *mut xmlNodePtr;
                if temp.is_null() {
                    xmlXPathErrMemory(
                        0 as xmlXPathContextPtr,
                        b"merging nodeset\n\0" as *const u8 as *const i8,
                    );
                    return 0 as xmlNodeSetPtr;
                }
                let fresh121 = unsafe { &mut ((*val1).nodeTab) };
                *fresh121 = temp;
                (unsafe { (*val1).nodeMax *= 2 as i32 });
            }
            if (unsafe { (*n2).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
                let mut ns: xmlNsPtr = n2 as xmlNsPtr;
                let fresh122 = unsafe { &mut ((*val1).nodeNr) };
                let fresh123 = *fresh122;
                *fresh122 = *fresh122 + 1;
                let fresh124 = unsafe { &mut (*((*val1).nodeTab).offset(fresh123 as isize)) };
                *fresh124 = xmlXPathNodeSetDupNs((unsafe { (*ns).next }) as xmlNodePtr, ns);
            } else {
                let fresh125 = unsafe { &mut ((*val1).nodeNr) };
                let fresh126 = *fresh125;
                *fresh125 = *fresh125 + 1;
                let fresh127 = unsafe { &mut (*((*val1).nodeTab).offset(fresh126 as isize)) };
                *fresh127 = n2;
            }
        }
        i += 1;
    }
    return val1;
}
extern "C" fn xmlXPathNodeSetMergeAndClear(
    mut set1: xmlNodeSetPtr,
    mut set2: xmlNodeSetPtr,
) -> xmlNodeSetPtr {
    let mut current_block: u64;
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    let mut initNbSet1: i32 = 0;
    let mut n1: xmlNodePtr = 0 as *mut xmlNode;
    let mut n2: xmlNodePtr = 0 as *mut xmlNode;
    initNbSet1 = unsafe { (*set1).nodeNr };
    i = 0 as i32;
    while i < (unsafe { (*set2).nodeNr }) {
        n2 = unsafe { *((*set2).nodeTab).offset(i as isize) };
        j = 0 as i32;
        loop {
            if !(j < initNbSet1) {
                current_block = 9606288038608642794;
                break;
            }
            n1 = unsafe { *((*set1).nodeTab).offset(j as isize) };
            if n1 == n2 {
                current_block = 12675440807659640239;
                break;
            }
            if (unsafe { (*n1).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
                && (unsafe { (*n2).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
            {
                if (unsafe { (*(n1 as xmlNsPtr)).next }) == (unsafe { (*(n2 as xmlNsPtr)).next })
                    && (unsafe { xmlStrEqual((*(n1 as xmlNsPtr)).prefix, (*(n2 as xmlNsPtr)).prefix) }) != 0
                {
                    let fresh128 = unsafe { &mut (*((*set2).nodeTab).offset(i as isize)) };
                    *fresh128 = 0 as xmlNodePtr;
                    xmlXPathNodeSetFreeNs(n2 as xmlNsPtr);
                    current_block = 12675440807659640239;
                    break;
                }
            }
            j += 1;
        }
        match current_block {
            9606288038608642794 => {
                if (unsafe { (*set1).nodeMax }) == 0 as i32 {
                    let fresh129 = unsafe { &mut ((*set1).nodeTab) };
                    *fresh129 = (unsafe { xmlMalloc.expect("non-null function pointer")(
                        (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
                    ) }) as *mut xmlNodePtr;
                    if (unsafe { (*set1).nodeTab }).is_null() {
                        xmlXPathErrMemory(
                            0 as xmlXPathContextPtr,
                            b"merging nodeset\n\0" as *const u8 as *const i8,
                        );
                        return 0 as xmlNodeSetPtr;
                    }
                    (unsafe { memset(
                        (*set1).nodeTab as *mut libc::c_void,
                        0 as i32,
                        (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
                    ) });
                    (unsafe { (*set1).nodeMax = 10 as i32 });
                } else if (unsafe { (*set1).nodeNr }) >= (unsafe { (*set1).nodeMax }) {
                    let mut temp: *mut xmlNodePtr = 0 as *mut xmlNodePtr;
                    if (unsafe { (*set1).nodeMax }) >= 10000000 as i32 {
                        xmlXPathErrMemory(
                            0 as xmlXPathContextPtr,
                            b"merging nodeset hit limit\n\0" as *const u8 as *const i8,
                        );
                        return 0 as xmlNodeSetPtr;
                    }
                    temp =
                        (unsafe { xmlRealloc.expect("non-null function pointer")(
                            (*set1).nodeTab as *mut libc::c_void,
                            (((*set1).nodeMax * 2 as i32) as u64)
                                .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
                        ) }) as *mut xmlNodePtr;
                    if temp.is_null() {
                        xmlXPathErrMemory(
                            0 as xmlXPathContextPtr,
                            b"merging nodeset\n\0" as *const u8 as *const i8,
                        );
                        return 0 as xmlNodeSetPtr;
                    }
                    let fresh130 = unsafe { &mut ((*set1).nodeTab) };
                    *fresh130 = temp;
                    (unsafe { (*set1).nodeMax *= 2 as i32 });
                }
                let fresh131 = unsafe { &mut ((*set1).nodeNr) };
                let fresh132 = *fresh131;
                *fresh131 = *fresh131 + 1;
                let fresh133 = unsafe { &mut (*((*set1).nodeTab).offset(fresh132 as isize)) };
                *fresh133 = n2;
            }
            _ => {}
        }
        i += 1;
    }
    (unsafe { (*set2).nodeNr = 0 as i32 });
    return set1;
}
extern "C" fn xmlXPathNodeSetMergeAndClearNoDupls(
    mut set1: xmlNodeSetPtr,
    mut set2: xmlNodeSetPtr,
) -> xmlNodeSetPtr {
    let mut i: i32 = 0;
    let mut n2: xmlNodePtr = 0 as *mut xmlNode;
    i = 0 as i32;
    while i < (unsafe { (*set2).nodeNr }) {
        n2 = unsafe { *((*set2).nodeTab).offset(i as isize) };
        if (unsafe { (*set1).nodeMax }) == 0 as i32 {
            let fresh134 = unsafe { &mut ((*set1).nodeTab) };
            *fresh134 = (unsafe { xmlMalloc.expect("non-null function pointer")(
                (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
            ) }) as *mut xmlNodePtr;
            if (unsafe { (*set1).nodeTab }).is_null() {
                xmlXPathErrMemory(
                    0 as xmlXPathContextPtr,
                    b"merging nodeset\n\0" as *const u8 as *const i8,
                );
                return 0 as xmlNodeSetPtr;
            }
            (unsafe { memset(
                (*set1).nodeTab as *mut libc::c_void,
                0 as i32,
                (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
            ) });
            (unsafe { (*set1).nodeMax = 10 as i32 });
        } else if (unsafe { (*set1).nodeNr }) >= (unsafe { (*set1).nodeMax }) {
            let mut temp: *mut xmlNodePtr = 0 as *mut xmlNodePtr;
            if (unsafe { (*set1).nodeMax }) >= 10000000 as i32 {
                xmlXPathErrMemory(
                    0 as xmlXPathContextPtr,
                    b"merging nodeset hit limit\n\0" as *const u8 as *const i8,
                );
                return 0 as xmlNodeSetPtr;
            }
            temp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                (*set1).nodeTab as *mut libc::c_void,
                (((*set1).nodeMax * 2 as i32) as u64)
                    .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
            ) }) as *mut xmlNodePtr;
            if temp.is_null() {
                xmlXPathErrMemory(
                    0 as xmlXPathContextPtr,
                    b"merging nodeset\n\0" as *const u8 as *const i8,
                );
                return 0 as xmlNodeSetPtr;
            }
            let fresh135 = unsafe { &mut ((*set1).nodeTab) };
            *fresh135 = temp;
            (unsafe { (*set1).nodeMax *= 2 as i32 });
        }
        let fresh136 = unsafe { &mut ((*set1).nodeNr) };
        let fresh137 = *fresh136;
        *fresh136 = *fresh136 + 1;
        let fresh138 = unsafe { &mut (*((*set1).nodeTab).offset(fresh137 as isize)) };
        *fresh138 = n2;
        i += 1;
    }
    (unsafe { (*set2).nodeNr = 0 as i32 });
    return set1;
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeSetDel(mut cur: xmlNodeSetPtr, mut val: xmlNodePtr) {
    let mut i: i32 = 0;
    if cur.is_null() {
        return;
    }
    if val.is_null() {
        return;
    }
    i = 0 as i32;
    while i < (unsafe { (*cur).nodeNr }) {
        if (unsafe { *((*cur).nodeTab).offset(i as isize) }) == val {
            break;
        }
        i += 1;
    }
    if i >= (unsafe { (*cur).nodeNr }) {
        return;
    }
    if !(unsafe { *((*cur).nodeTab).offset(i as isize) }).is_null()
        && (unsafe { (**((*cur).nodeTab).offset(i as isize)).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
    {
        xmlXPathNodeSetFreeNs((unsafe { *((*cur).nodeTab).offset(i as isize) }) as xmlNsPtr);
    }
    let fresh139 = unsafe { &mut ((*cur).nodeNr) };
    *fresh139 -= 1;
    while i < (unsafe { (*cur).nodeNr }) {
        let fresh140 = unsafe { &mut (*((*cur).nodeTab).offset(i as isize)) };
        *fresh140 = unsafe { *((*cur).nodeTab).offset((i + 1 as i32) as isize) };
        i += 1;
    }
    let fresh141 = unsafe { &mut (*((*cur).nodeTab).offset((*cur).nodeNr as isize)) };
    *fresh141 = 0 as xmlNodePtr;
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeSetRemove(mut cur: xmlNodeSetPtr, mut val: i32) {
    if cur.is_null() {
        return;
    }
    if val >= (unsafe { (*cur).nodeNr }) {
        return;
    }
    if !(unsafe { *((*cur).nodeTab).offset(val as isize) }).is_null()
        && (unsafe { (**((*cur).nodeTab).offset(val as isize)).type_0 }) as u32
            == XML_NAMESPACE_DECL as i32 as u32
    {
        xmlXPathNodeSetFreeNs((unsafe { *((*cur).nodeTab).offset(val as isize) }) as xmlNsPtr);
    }
    let fresh142 = unsafe { &mut ((*cur).nodeNr) };
    *fresh142 -= 1;
    while val < (unsafe { (*cur).nodeNr }) {
        let fresh143 = unsafe { &mut (*((*cur).nodeTab).offset(val as isize)) };
        *fresh143 = unsafe { *((*cur).nodeTab).offset((val + 1 as i32) as isize) };
        val += 1;
    }
    let fresh144 = unsafe { &mut (*((*cur).nodeTab).offset((*cur).nodeNr as isize)) };
    *fresh144 = 0 as xmlNodePtr;
}
#[no_mangle]
pub extern "C" fn xmlXPathFreeNodeSet(mut obj: xmlNodeSetPtr) {
    if obj.is_null() {
        return;
    }
    if !(unsafe { (*obj).nodeTab }).is_null() {
        let mut i: i32 = 0;
        i = 0 as i32;
        while i < (unsafe { (*obj).nodeNr }) {
            if !(unsafe { *((*obj).nodeTab).offset(i as isize) }).is_null()
                && (unsafe { (**((*obj).nodeTab).offset(i as isize)).type_0 }) as u32
                    == XML_NAMESPACE_DECL as i32 as u32
            {
                xmlXPathNodeSetFreeNs((unsafe { *((*obj).nodeTab).offset(i as isize) }) as xmlNsPtr);
            }
            i += 1;
        }
        (unsafe { xmlFree.expect("non-null function pointer")((*obj).nodeTab as *mut libc::c_void) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(obj as *mut libc::c_void) });
}
extern "C" fn xmlXPathNodeSetClearFromPos(
    mut set: xmlNodeSetPtr,
    mut pos: i32,
    mut hasNsNodes: i32,
) {
    if set.is_null() || pos >= (unsafe { (*set).nodeNr }) {
        return;
    } else {
        if hasNsNodes != 0 {
            let mut i: i32 = 0;
            let mut node: xmlNodePtr = 0 as *mut xmlNode;
            i = pos;
            while i < (unsafe { (*set).nodeNr }) {
                node = unsafe { *((*set).nodeTab).offset(i as isize) };
                if !node.is_null() && (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
                    xmlXPathNodeSetFreeNs(node as xmlNsPtr);
                }
                i += 1;
            }
        }
    }
    (unsafe { (*set).nodeNr = pos });
}
extern "C" fn xmlXPathNodeSetClear(mut set: xmlNodeSetPtr, mut hasNsNodes: i32) {
    xmlXPathNodeSetClearFromPos(set, 0 as i32, hasNsNodes);
}
extern "C" fn xmlXPathNodeSetKeepLast(mut set: xmlNodeSetPtr) {
    let mut i: i32 = 0;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if set.is_null() || (unsafe { (*set).nodeNr }) <= 1 as i32 {
        return;
    }
    i = 0 as i32;
    while i < (unsafe { (*set).nodeNr }) - 1 as i32 {
        node = unsafe { *((*set).nodeTab).offset(i as isize) };
        if !node.is_null() && (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
            xmlXPathNodeSetFreeNs(node as xmlNsPtr);
        }
        i += 1;
    }
    let fresh145 = unsafe { &mut (*((*set).nodeTab).offset(0 as i32 as isize)) };
    *fresh145 = unsafe { *((*set).nodeTab).offset(((*set).nodeNr - 1 as i32) as isize) };
    (unsafe { (*set).nodeNr = 1 as i32 });
}
extern "C" fn xmlXPathFreeValueTree(mut obj: xmlNodeSetPtr) {
    let mut i: i32 = 0;
    if obj.is_null() {
        return;
    }
    if !(unsafe { (*obj).nodeTab }).is_null() {
        i = 0 as i32;
        while i < (unsafe { (*obj).nodeNr }) {
            if !(unsafe { *((*obj).nodeTab).offset(i as isize) }).is_null() {
                if (unsafe { (**((*obj).nodeTab).offset(i as isize)).type_0 }) as u32
                    == XML_NAMESPACE_DECL as i32 as u32
                {
                    xmlXPathNodeSetFreeNs((unsafe { *((*obj).nodeTab).offset(i as isize) }) as xmlNsPtr);
                } else {
                    (unsafe { xmlFreeNodeList(*((*obj).nodeTab).offset(i as isize)) });
                }
            }
            i += 1;
        }
        (unsafe { xmlFree.expect("non-null function pointer")((*obj).nodeTab as *mut libc::c_void) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(obj as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlXPathNewNodeSet(mut val: xmlNodePtr) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathObject>() as u64
    ) }) as xmlXPathObjectPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"creating nodeset\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathObjectPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathObject>() as u64,
    ) });
    (unsafe { (*ret).type_0 = XPATH_NODESET });
    (unsafe { (*ret).boolval = 0 as i32 });
    let fresh146 = unsafe { &mut ((*ret).nodesetval) };
    *fresh146 = xmlXPathNodeSetCreate(val);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathNewValueTree(mut val: xmlNodePtr) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathObject>() as u64
    ) }) as xmlXPathObjectPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"creating result value tree\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathObjectPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathObject>() as u64,
    ) });
    (unsafe { (*ret).type_0 = XPATH_XSLT_TREE });
    (unsafe { (*ret).boolval = 1 as i32 });
    let fresh147 = unsafe { &mut ((*ret).user) };
    *fresh147 = val as *mut libc::c_void;
    let fresh148 = unsafe { &mut ((*ret).nodesetval) };
    *fresh148 = xmlXPathNodeSetCreate(val);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathNewNodeSetList(mut val: xmlNodeSetPtr) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut i: i32 = 0;
    if val.is_null() {
        ret = 0 as xmlXPathObjectPtr;
    } else if (unsafe { (*val).nodeTab }).is_null() {
        ret = xmlXPathNewNodeSet(0 as xmlNodePtr);
    } else {
        ret = xmlXPathNewNodeSet(unsafe { *((*val).nodeTab).offset(0 as i32 as isize) });
        if !ret.is_null() {
            i = 1 as i32;
            while i < (unsafe { (*val).nodeNr }) {
                if xmlXPathNodeSetAddUnique(unsafe { (*ret).nodesetval }, unsafe { *((*val).nodeTab).offset(i as isize) })
                    < 0 as i32
                {
                    break;
                }
                i += 1;
            }
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathWrapNodeSet(mut val: xmlNodeSetPtr) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathObject>() as u64
    ) }) as xmlXPathObjectPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"creating node set object\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathObjectPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathObject>() as u64,
    ) });
    (unsafe { (*ret).type_0 = XPATH_NODESET });
    let fresh149 = unsafe { &mut ((*ret).nodesetval) };
    *fresh149 = val;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathFreeNodeSetList(mut obj: xmlXPathObjectPtr) {
    if obj.is_null() {
        return;
    }
    (unsafe { xmlFree.expect("non-null function pointer")(obj as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlXPathDifference(
    mut nodes1: xmlNodeSetPtr,
    mut nodes2: xmlNodeSetPtr,
) -> xmlNodeSetPtr {
    let mut ret: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut i: i32 = 0;
    let mut l1: i32 = 0;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if nodes2.is_null() || (unsafe { (*nodes2).nodeNr }) == 0 as i32 || (unsafe { (*nodes2).nodeTab }).is_null() {
        return nodes1;
    }
    ret = xmlXPathNodeSetCreate(0 as xmlNodePtr);
    if nodes1.is_null() || (unsafe { (*nodes1).nodeNr }) == 0 as i32 || (unsafe { (*nodes1).nodeTab }).is_null() {
        return ret;
    }
    l1 = if !nodes1.is_null() {
        unsafe { (*nodes1).nodeNr }
    } else {
        0 as i32
    };
    i = 0 as i32;
    while i < l1 {
        cur = if !nodes1.is_null() && i >= 0 as i32 && i < (unsafe { (*nodes1).nodeNr }) {
            unsafe { *((*nodes1).nodeTab).offset(i as isize) }
        } else {
            0 as xmlNodePtr
        };
        if xmlXPathNodeSetContains(nodes2, cur) == 0 {
            if xmlXPathNodeSetAddUnique(ret, cur) < 0 as i32 {
                break;
            }
        }
        i += 1;
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathIntersection(
    mut nodes1: xmlNodeSetPtr,
    mut nodes2: xmlNodeSetPtr,
) -> xmlNodeSetPtr {
    let mut ret: xmlNodeSetPtr = xmlXPathNodeSetCreate(0 as xmlNodePtr);
    let mut i: i32 = 0;
    let mut l1: i32 = 0;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if ret.is_null() {
        return ret;
    }
    if nodes1.is_null() || (unsafe { (*nodes1).nodeNr }) == 0 as i32 || (unsafe { (*nodes1).nodeTab }).is_null() {
        return ret;
    }
    if nodes2.is_null() || (unsafe { (*nodes2).nodeNr }) == 0 as i32 || (unsafe { (*nodes2).nodeTab }).is_null() {
        return ret;
    }
    l1 = if !nodes1.is_null() {
        unsafe { (*nodes1).nodeNr }
    } else {
        0 as i32
    };
    i = 0 as i32;
    while i < l1 {
        cur = if !nodes1.is_null() && i >= 0 as i32 && i < (unsafe { (*nodes1).nodeNr }) {
            unsafe { *((*nodes1).nodeTab).offset(i as isize) }
        } else {
            0 as xmlNodePtr
        };
        if xmlXPathNodeSetContains(nodes2, cur) != 0 {
            if xmlXPathNodeSetAddUnique(ret, cur) < 0 as i32 {
                break;
            }
        }
        i += 1;
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathDistinctSorted(mut nodes: xmlNodeSetPtr) -> xmlNodeSetPtr {
    let mut ret: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut hash: xmlHashTablePtr = 0 as *mut xmlHashTable;
    let mut i: i32 = 0;
    let mut l: i32 = 0;
    let mut strval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if nodes.is_null() || (unsafe { (*nodes).nodeNr }) == 0 as i32 || (unsafe { (*nodes).nodeTab }).is_null() {
        return nodes;
    }
    ret = xmlXPathNodeSetCreate(0 as xmlNodePtr);
    if ret.is_null() {
        return ret;
    }
    l = if !nodes.is_null() {
        unsafe { (*nodes).nodeNr }
    } else {
        0 as i32
    };
    hash = unsafe { xmlHashCreate(l) };
    i = 0 as i32;
    while i < l {
        cur = if !nodes.is_null() && i >= 0 as i32 && i < (unsafe { (*nodes).nodeNr }) {
            unsafe { *((*nodes).nodeTab).offset(i as isize) }
        } else {
            0 as xmlNodePtr
        };
        strval = xmlXPathCastNodeToString(cur);
        if (unsafe { xmlHashLookup(hash, strval) }).is_null() {
            (unsafe { xmlHashAddEntry(hash, strval, strval as *mut libc::c_void) });
            if xmlXPathNodeSetAddUnique(ret, cur) < 0 as i32 {
                break;
            }
        } else {
            (unsafe { xmlFree.expect("non-null function pointer")(strval as *mut libc::c_void) });
        }
        i += 1;
    }
    (unsafe { xmlHashFree(
        hash,
        Some(
            xmlHashDefaultDeallocator
                as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        ),
    ) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathDistinct(mut nodes: xmlNodeSetPtr) -> xmlNodeSetPtr {
    if nodes.is_null() || (unsafe { (*nodes).nodeNr }) == 0 as i32 || (unsafe { (*nodes).nodeTab }).is_null() {
        return nodes;
    }
    xmlXPathNodeSetSort(nodes);
    return xmlXPathDistinctSorted(nodes);
}
#[no_mangle]
pub extern "C" fn xmlXPathHasSameNodes(
    mut nodes1: xmlNodeSetPtr,
    mut nodes2: xmlNodeSetPtr,
) -> i32 {
    let mut i: i32 = 0;
    let mut l: i32 = 0;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if nodes1.is_null()
        || (unsafe { (*nodes1).nodeNr }) == 0 as i32
        || (unsafe { (*nodes1).nodeTab }).is_null()
        || (nodes2.is_null() || (unsafe { (*nodes2).nodeNr }) == 0 as i32 || (unsafe { (*nodes2).nodeTab }).is_null())
    {
        return 0 as i32;
    }
    l = if !nodes1.is_null() {
        unsafe { (*nodes1).nodeNr }
    } else {
        0 as i32
    };
    i = 0 as i32;
    while i < l {
        cur = if !nodes1.is_null() && i >= 0 as i32 && i < (unsafe { (*nodes1).nodeNr }) {
            unsafe { *((*nodes1).nodeTab).offset(i as isize) }
        } else {
            0 as xmlNodePtr
        };
        if xmlXPathNodeSetContains(nodes2, cur) != 0 {
            return 1 as i32;
        }
        i += 1;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeLeadingSorted(
    mut nodes: xmlNodeSetPtr,
    mut node: xmlNodePtr,
) -> xmlNodeSetPtr {
    let mut i: i32 = 0;
    let mut l: i32 = 0;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut ret: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    if node.is_null() {
        return nodes;
    }
    ret = xmlXPathNodeSetCreate(0 as xmlNodePtr);
    if ret.is_null() {
        return ret;
    }
    if nodes.is_null()
        || (unsafe { (*nodes).nodeNr }) == 0 as i32
        || (unsafe { (*nodes).nodeTab }).is_null()
        || xmlXPathNodeSetContains(nodes, node) == 0
    {
        return ret;
    }
    l = if !nodes.is_null() {
        unsafe { (*nodes).nodeNr }
    } else {
        0 as i32
    };
    i = 0 as i32;
    while i < l {
        cur = if !nodes.is_null() && i >= 0 as i32 && i < (unsafe { (*nodes).nodeNr }) {
            unsafe { *((*nodes).nodeTab).offset(i as isize) }
        } else {
            0 as xmlNodePtr
        };
        if cur == node {
            break;
        }
        if xmlXPathNodeSetAddUnique(ret, cur) < 0 as i32 {
            break;
        }
        i += 1;
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeLeading(
    mut nodes: xmlNodeSetPtr,
    mut node: xmlNodePtr,
) -> xmlNodeSetPtr {
    xmlXPathNodeSetSort(nodes);
    return xmlXPathNodeLeadingSorted(nodes, node);
}
#[no_mangle]
pub extern "C" fn xmlXPathLeadingSorted(
    mut nodes1: xmlNodeSetPtr,
    mut nodes2: xmlNodeSetPtr,
) -> xmlNodeSetPtr {
    if nodes2.is_null() || (unsafe { (*nodes2).nodeNr }) == 0 as i32 || (unsafe { (*nodes2).nodeTab }).is_null() {
        return nodes1;
    }
    return xmlXPathNodeLeadingSorted(
        nodes1,
        if !nodes2.is_null() && 1 as i32 >= 0 as i32 && (1 as i32) < (unsafe { (*nodes2).nodeNr }) {
            unsafe { *((*nodes2).nodeTab).offset(1 as i32 as isize) }
        } else {
            0 as xmlNodePtr
        },
    );
}
#[no_mangle]
pub extern "C" fn xmlXPathLeading(
    mut nodes1: xmlNodeSetPtr,
    mut nodes2: xmlNodeSetPtr,
) -> xmlNodeSetPtr {
    if nodes2.is_null() || (unsafe { (*nodes2).nodeNr }) == 0 as i32 || (unsafe { (*nodes2).nodeTab }).is_null() {
        return nodes1;
    }
    if nodes1.is_null() || (unsafe { (*nodes1).nodeNr }) == 0 as i32 || (unsafe { (*nodes1).nodeTab }).is_null() {
        return xmlXPathNodeSetCreate(0 as xmlNodePtr);
    }
    xmlXPathNodeSetSort(nodes1);
    xmlXPathNodeSetSort(nodes2);
    return xmlXPathNodeLeadingSorted(
        nodes1,
        if !nodes2.is_null() && 1 as i32 >= 0 as i32 && (1 as i32) < (unsafe { (*nodes2).nodeNr }) {
            unsafe { *((*nodes2).nodeTab).offset(1 as i32 as isize) }
        } else {
            0 as xmlNodePtr
        },
    );
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeTrailingSorted(
    mut nodes: xmlNodeSetPtr,
    mut node: xmlNodePtr,
) -> xmlNodeSetPtr {
    let mut i: i32 = 0;
    let mut l: i32 = 0;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut ret: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    if node.is_null() {
        return nodes;
    }
    ret = xmlXPathNodeSetCreate(0 as xmlNodePtr);
    if ret.is_null() {
        return ret;
    }
    if nodes.is_null()
        || (unsafe { (*nodes).nodeNr }) == 0 as i32
        || (unsafe { (*nodes).nodeTab }).is_null()
        || xmlXPathNodeSetContains(nodes, node) == 0
    {
        return ret;
    }
    l = if !nodes.is_null() {
        unsafe { (*nodes).nodeNr }
    } else {
        0 as i32
    };
    i = l - 1 as i32;
    while i >= 0 as i32 {
        cur = if !nodes.is_null() && i >= 0 as i32 && i < (unsafe { (*nodes).nodeNr }) {
            unsafe { *((*nodes).nodeTab).offset(i as isize) }
        } else {
            0 as xmlNodePtr
        };
        if cur == node {
            break;
        }
        if xmlXPathNodeSetAddUnique(ret, cur) < 0 as i32 {
            break;
        }
        i -= 1;
    }
    xmlXPathNodeSetSort(ret);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeTrailing(
    mut nodes: xmlNodeSetPtr,
    mut node: xmlNodePtr,
) -> xmlNodeSetPtr {
    xmlXPathNodeSetSort(nodes);
    return xmlXPathNodeTrailingSorted(nodes, node);
}
#[no_mangle]
pub extern "C" fn xmlXPathTrailingSorted(
    mut nodes1: xmlNodeSetPtr,
    mut nodes2: xmlNodeSetPtr,
) -> xmlNodeSetPtr {
    if nodes2.is_null() || (unsafe { (*nodes2).nodeNr }) == 0 as i32 || (unsafe { (*nodes2).nodeTab }).is_null() {
        return nodes1;
    }
    return xmlXPathNodeTrailingSorted(
        nodes1,
        if !nodes2.is_null() && 0 as i32 >= 0 as i32 && (0 as i32) < (unsafe { (*nodes2).nodeNr }) {
            unsafe { *((*nodes2).nodeTab).offset(0 as i32 as isize) }
        } else {
            0 as xmlNodePtr
        },
    );
}
#[no_mangle]
pub extern "C" fn xmlXPathTrailing(
    mut nodes1: xmlNodeSetPtr,
    mut nodes2: xmlNodeSetPtr,
) -> xmlNodeSetPtr {
    if nodes2.is_null() || (unsafe { (*nodes2).nodeNr }) == 0 as i32 || (unsafe { (*nodes2).nodeTab }).is_null() {
        return nodes1;
    }
    if nodes1.is_null() || (unsafe { (*nodes1).nodeNr }) == 0 as i32 || (unsafe { (*nodes1).nodeTab }).is_null() {
        return xmlXPathNodeSetCreate(0 as xmlNodePtr);
    }
    xmlXPathNodeSetSort(nodes1);
    xmlXPathNodeSetSort(nodes2);
    return xmlXPathNodeTrailingSorted(
        nodes1,
        if !nodes2.is_null() && 0 as i32 >= 0 as i32 && (0 as i32) < (unsafe { (*nodes2).nodeNr }) {
            unsafe { *((*nodes2).nodeTab).offset(0 as i32 as isize) }
        } else {
            0 as xmlNodePtr
        },
    );
}
#[no_mangle]
pub extern "C" fn xmlXPathRegisterFunc(
    mut ctxt: xmlXPathContextPtr,
    mut name: *const xmlChar,
    mut f: xmlXPathFunction,
) -> i32 {
    return xmlXPathRegisterFuncNS(ctxt, name, 0 as *const xmlChar, f);
}
#[no_mangle]
pub extern "C" fn xmlXPathRegisterFuncNS(
    mut ctxt: xmlXPathContextPtr,
    mut name: *const xmlChar,
    mut ns_uri: *const xmlChar,
    mut f: xmlXPathFunction,
) -> i32 {
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if name.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).funcHash }).is_null() {
        let fresh150 = unsafe { &mut ((*ctxt).funcHash) };
        *fresh150 = unsafe { xmlHashCreate(0 as i32) };
    }
    if (unsafe { (*ctxt).funcHash }).is_null() {
        return -(1 as i32);
    }
    if f.is_none() {
        return unsafe { xmlHashRemoveEntry2((*ctxt).funcHash, name, ns_uri, None) };
    }
    return unsafe { xmlHashAddEntry2(
        (*ctxt).funcHash,
        name,
        ns_uri,
        ::std::mem::transmute::<xmlXPathFunction, *mut libc::c_void>(f),
    ) };
}
#[no_mangle]
pub extern "C" fn xmlXPathRegisterFuncLookup(
    mut ctxt: xmlXPathContextPtr,
    mut f: xmlXPathFuncLookupFunc,
    mut funcCtxt: *mut libc::c_void,
) {
    if ctxt.is_null() {
        return;
    }
    let fresh151 = unsafe { &mut ((*ctxt).funcLookupFunc) };
    *fresh151 = f;
    let fresh152 = unsafe { &mut ((*ctxt).funcLookupData) };
    *fresh152 = funcCtxt;
}
#[no_mangle]
pub extern "C" fn xmlXPathFunctionLookup(
    mut ctxt: xmlXPathContextPtr,
    mut name: *const xmlChar,
) -> xmlXPathFunction {
    if ctxt.is_null() {
        return None;
    }
    if unsafe { ((*ctxt).funcLookupFunc).is_some() } {
        let mut ret: xmlXPathFunction = None;
        let mut f: xmlXPathFuncLookupFunc = None;
        f = unsafe { (*ctxt).funcLookupFunc };
        ret = unsafe { f.expect("non-null function pointer")(
            (*ctxt).funcLookupData,
            name,
            0 as *const xmlChar,
        ) };
        if ret.is_some() {
            return ret;
        }
    }
    return xmlXPathFunctionLookupNS(ctxt, name, 0 as *const xmlChar);
}
#[no_mangle]
pub extern "C" fn xmlXPathFunctionLookupNS(
    mut ctxt: xmlXPathContextPtr,
    mut name: *const xmlChar,
    mut ns_uri: *const xmlChar,
) -> xmlXPathFunction {
    let mut ret: xmlXPathFunction = None;
    if ctxt.is_null() {
        return None;
    }
    if name.is_null() {
        return None;
    }
    if unsafe { ((*ctxt).funcLookupFunc).is_some() } {
        let mut f: xmlXPathFuncLookupFunc = None;
        f = unsafe { (*ctxt).funcLookupFunc };
        ret = unsafe { f.expect("non-null function pointer")((*ctxt).funcLookupData, name, ns_uri) };
        if ret.is_some() {
            return ret;
        }
    }
    if (unsafe { (*ctxt).funcHash }).is_null() {
        return None;
    }
    ret = unsafe { ::std::mem::transmute::<*mut libc::c_void, xmlXPathFunction>(xmlHashLookup2(
        (*ctxt).funcHash,
        name,
        ns_uri,
    )) };
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathRegisteredFuncsCleanup(mut ctxt: xmlXPathContextPtr) {
    if ctxt.is_null() {
        return;
    }
    (unsafe { xmlHashFree((*ctxt).funcHash, None) });
    let fresh153 = unsafe { &mut ((*ctxt).funcHash) };
    *fresh153 = 0 as xmlHashTablePtr;
}
#[no_mangle]
pub extern "C" fn xmlXPathRegisterVariable(
    mut ctxt: xmlXPathContextPtr,
    mut name: *const xmlChar,
    mut value: xmlXPathObjectPtr,
) -> i32 {
    return xmlXPathRegisterVariableNS(ctxt, name, 0 as *const xmlChar, value);
}
#[no_mangle]
pub extern "C" fn xmlXPathRegisterVariableNS(
    mut ctxt: xmlXPathContextPtr,
    mut name: *const xmlChar,
    mut ns_uri: *const xmlChar,
    mut value: xmlXPathObjectPtr,
) -> i32 {
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if name.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).varHash }).is_null() {
        let fresh154 = unsafe { &mut ((*ctxt).varHash) };
        *fresh154 = unsafe { xmlHashCreate(0 as i32) };
    }
    if (unsafe { (*ctxt).varHash }).is_null() {
        return -(1 as i32);
    }
    if value.is_null() {
        return unsafe { xmlHashRemoveEntry2(
            (*ctxt).varHash,
            name,
            ns_uri,
            Some(
                xmlXPathFreeObjectEntry
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
        ) };
    }
    return unsafe { xmlHashUpdateEntry2(
        (*ctxt).varHash,
        name,
        ns_uri,
        value as *mut libc::c_void,
        Some(
            xmlXPathFreeObjectEntry
                as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        ),
    ) };
}
#[no_mangle]
pub extern "C" fn xmlXPathRegisterVariableLookup(
    mut ctxt: xmlXPathContextPtr,
    mut f: xmlXPathVariableLookupFunc,
    mut data: *mut libc::c_void,
) {
    if ctxt.is_null() {
        return;
    }
    let fresh155 = unsafe { &mut ((*ctxt).varLookupFunc) };
    *fresh155 = f;
    let fresh156 = unsafe { &mut ((*ctxt).varLookupData) };
    *fresh156 = data;
}
#[no_mangle]
pub extern "C" fn xmlXPathVariableLookup(
    mut ctxt: xmlXPathContextPtr,
    mut name: *const xmlChar,
) -> xmlXPathObjectPtr {
    if ctxt.is_null() {
        return 0 as xmlXPathObjectPtr;
    }
    if unsafe { ((*ctxt).varLookupFunc).is_some() } {
        let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
        ret = unsafe { ((*ctxt).varLookupFunc).expect("non-null function pointer")(
            (*ctxt).varLookupData,
            name,
            0 as *const xmlChar,
        ) };
        return ret;
    }
    return xmlXPathVariableLookupNS(ctxt, name, 0 as *const xmlChar);
}
#[no_mangle]
pub extern "C" fn xmlXPathVariableLookupNS(
    mut ctxt: xmlXPathContextPtr,
    mut name: *const xmlChar,
    mut ns_uri: *const xmlChar,
) -> xmlXPathObjectPtr {
    if ctxt.is_null() {
        return 0 as xmlXPathObjectPtr;
    }
    if unsafe { ((*ctxt).varLookupFunc).is_some() } {
        let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
        ret = unsafe { ((*ctxt).varLookupFunc).expect("non-null function pointer")(
            (*ctxt).varLookupData,
            name,
            ns_uri,
        ) };
        if !ret.is_null() {
            return ret;
        }
    }
    if (unsafe { (*ctxt).varHash }).is_null() {
        return 0 as xmlXPathObjectPtr;
    }
    if name.is_null() {
        return 0 as xmlXPathObjectPtr;
    }
    return xmlXPathCacheObjectCopy(
        ctxt,
        (unsafe { xmlHashLookup2((*ctxt).varHash, name, ns_uri) }) as xmlXPathObjectPtr,
    );
}
#[no_mangle]
pub extern "C" fn xmlXPathRegisteredVariablesCleanup(mut ctxt: xmlXPathContextPtr) {
    if ctxt.is_null() {
        return;
    }
    (unsafe { xmlHashFree(
        (*ctxt).varHash,
        Some(
            xmlXPathFreeObjectEntry
                as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        ),
    ) });
    let fresh157 = unsafe { &mut ((*ctxt).varHash) };
    *fresh157 = 0 as xmlHashTablePtr;
}
#[no_mangle]
pub extern "C" fn xmlXPathRegisterNs(
    mut ctxt: xmlXPathContextPtr,
    mut prefix: *const xmlChar,
    mut ns_uri: *const xmlChar,
) -> i32 {
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if prefix.is_null() {
        return -(1 as i32);
    }
    if (unsafe { *prefix.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).nsHash }).is_null() {
        let fresh158 = unsafe { &mut ((*ctxt).nsHash) };
        *fresh158 = unsafe { xmlHashCreate(10 as i32) };
    }
    if (unsafe { (*ctxt).nsHash }).is_null() {
        return -(1 as i32);
    }
    if ns_uri.is_null() {
        return unsafe { xmlHashRemoveEntry(
            (*ctxt).nsHash,
            prefix,
            Some(
                xmlHashDefaultDeallocator
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
        ) };
    }
    return unsafe { xmlHashUpdateEntry(
        (*ctxt).nsHash,
        prefix,
        xmlStrdup(ns_uri) as *mut libc::c_void,
        Some(
            xmlHashDefaultDeallocator
                as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        ),
    ) };
}
#[no_mangle]
pub extern "C" fn xmlXPathNsLookup(
    mut ctxt: xmlXPathContextPtr,
    mut prefix: *const xmlChar,
) -> *const xmlChar {
    if ctxt.is_null() {
        return 0 as *const xmlChar;
    }
    if prefix.is_null() {
        return 0 as *const xmlChar;
    }
    if (unsafe { xmlStrEqual(prefix, b"xml\0" as *const u8 as *const i8 as *const xmlChar) }) != 0 {
        return b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
            as *const xmlChar;
    }
    if !(unsafe { (*ctxt).namespaces }).is_null() {
        let mut i: i32 = 0;
        i = 0 as i32;
        while i < (unsafe { (*ctxt).nsNr }) {
            if !(unsafe { *((*ctxt).namespaces).offset(i as isize) }).is_null()
                && (unsafe { xmlStrEqual((**((*ctxt).namespaces).offset(i as isize)).prefix, prefix) }) != 0
            {
                return unsafe { (**((*ctxt).namespaces).offset(i as isize)).href };
            }
            i += 1;
        }
    }
    return (unsafe { xmlHashLookup((*ctxt).nsHash, prefix) }) as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlXPathRegisteredNsCleanup(mut ctxt: xmlXPathContextPtr) {
    if ctxt.is_null() {
        return;
    }
    (unsafe { xmlHashFree(
        (*ctxt).nsHash,
        Some(
            xmlHashDefaultDeallocator
                as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        ),
    ) });
    let fresh159 = unsafe { &mut ((*ctxt).nsHash) };
    *fresh159 = 0 as xmlHashTablePtr;
}
#[no_mangle]
pub extern "C" fn xmlXPathNewFloat(mut val: f64) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathObject>() as u64
    ) }) as xmlXPathObjectPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"creating float object\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathObjectPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathObject>() as u64,
    ) });
    (unsafe { (*ret).type_0 = XPATH_NUMBER });
    (unsafe { (*ret).floatval = val });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathNewBoolean(mut val: i32) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathObject>() as u64
    ) }) as xmlXPathObjectPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"creating boolean object\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathObjectPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathObject>() as u64,
    ) });
    (unsafe { (*ret).type_0 = XPATH_BOOLEAN });
    (unsafe { (*ret).boolval = (val != 0 as i32) as i32 });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathNewString(mut val: *const xmlChar) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathObject>() as u64
    ) }) as xmlXPathObjectPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"creating string object\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathObjectPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathObject>() as u64,
    ) });
    (unsafe { (*ret).type_0 = XPATH_STRING });
    if !val.is_null() {
        let fresh160 = unsafe { &mut ((*ret).stringval) };
        *fresh160 = unsafe { xmlStrdup(val) };
    } else {
        let fresh161 = unsafe { &mut ((*ret).stringval) };
        *fresh161 = unsafe { xmlStrdup(b"\0" as *const u8 as *const i8 as *const xmlChar) };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathWrapString(mut val: *mut xmlChar) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathObject>() as u64
    ) }) as xmlXPathObjectPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"creating string object\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathObjectPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathObject>() as u64,
    ) });
    (unsafe { (*ret).type_0 = XPATH_STRING });
    let fresh162 = unsafe { &mut ((*ret).stringval) };
    *fresh162 = val;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathNewCString(mut val: *const i8) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathObject>() as u64
    ) }) as xmlXPathObjectPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"creating string object\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathObjectPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathObject>() as u64,
    ) });
    (unsafe { (*ret).type_0 = XPATH_STRING });
    let fresh163 = unsafe { &mut ((*ret).stringval) };
    *fresh163 = unsafe { xmlStrdup(val as *mut xmlChar) };
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathWrapCString(mut val: *mut i8) -> xmlXPathObjectPtr {
    return xmlXPathWrapString(val as *mut xmlChar);
}
#[no_mangle]
pub extern "C" fn xmlXPathWrapExternal(mut val: *mut libc::c_void) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathObject>() as u64
    ) }) as xmlXPathObjectPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"creating user object\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathObjectPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathObject>() as u64,
    ) });
    (unsafe { (*ret).type_0 = XPATH_USERS });
    let fresh164 = unsafe { &mut ((*ret).user) };
    *fresh164 = val;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathObjectCopy(mut val: xmlXPathObjectPtr) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if val.is_null() {
        return 0 as xmlXPathObjectPtr;
    }
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathObject>() as u64
    ) }) as xmlXPathObjectPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"copying object\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathObjectPtr;
    }
    (unsafe { memcpy(
        ret as *mut libc::c_void,
        val as *const libc::c_void,
        ::std::mem::size_of::<xmlXPathObject>() as u64,
    ) });
    match (unsafe { (*val).type_0 }) as u32 {
        4 => {
            let fresh165 = unsafe { &mut ((*ret).stringval) };
            *fresh165 = unsafe { xmlStrdup((*val).stringval) };
        }
        9 | 1 => {
            let fresh166 = unsafe { &mut ((*ret).nodesetval) };
            *fresh166 = xmlXPathNodeSetMerge(0 as xmlNodeSetPtr, unsafe { (*val).nodesetval });
            (unsafe { (*ret).boolval = 0 as i32 });
        }
        8 => {
            let fresh167 = unsafe { &mut ((*ret).user) };
            *fresh167 = unsafe { (*val).user };
        }
        0 => {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlXPathObjectCopy: unsupported type %d\n\0" as *const u8 as *const i8,
                (*val).type_0 as u32,
            ) });
        }
        2 | 3 | _ => {}
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathFreeObject(mut obj: xmlXPathObjectPtr) {
    if obj.is_null() {
        return;
    }
    if (unsafe { (*obj).type_0 }) as u32 == XPATH_NODESET as i32 as u32
        || (unsafe { (*obj).type_0 }) as u32 == XPATH_XSLT_TREE as i32 as u32
    {
        if (unsafe { (*obj).boolval }) != 0 {
            (unsafe { (*obj).type_0 = XPATH_XSLT_TREE });
            if !(unsafe { (*obj).nodesetval }).is_null() {
                xmlXPathFreeValueTree(unsafe { (*obj).nodesetval });
            }
        } else if !(unsafe { (*obj).nodesetval }).is_null() {
            xmlXPathFreeNodeSet(unsafe { (*obj).nodesetval });
        }
    } else if (unsafe { (*obj).type_0 }) as u32 == XPATH_STRING as i32 as u32 {
        if !(unsafe { (*obj).stringval }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*obj).stringval as *mut libc::c_void) });
        }
    }
    (unsafe { xmlFree.expect("non-null function pointer")(obj as *mut libc::c_void) });
}
extern "C" fn xmlXPathFreeObjectEntry(mut obj: *mut libc::c_void, mut _name: *const xmlChar) {
    xmlXPathFreeObject(obj as xmlXPathObjectPtr);
}
extern "C" fn xmlXPathReleaseObject(mut ctxt: xmlXPathContextPtr, mut obj: xmlXPathObjectPtr) {
    let mut current_block: u64;
    if obj.is_null() {
        return;
    }
    if ctxt.is_null() || (unsafe { (*ctxt).cache }).is_null() {
        xmlXPathFreeObject(obj);
    } else {
        let mut cache: xmlXPathContextCachePtr = (unsafe { (*ctxt).cache }) as xmlXPathContextCachePtr;
        match (unsafe { (*obj).type_0 }) as u32 {
            1 | 9 => {
                if !(unsafe { (*obj).nodesetval }).is_null() {
                    if (unsafe { (*obj).boolval }) != 0 {
                        (unsafe { (*obj).type_0 = XPATH_XSLT_TREE });
                        xmlXPathFreeValueTree(unsafe { (*obj).nodesetval });
                        let fresh168 = unsafe { &mut ((*obj).nodesetval) };
                        *fresh168 = 0 as xmlNodeSetPtr;
                        current_block = 13678349939556791712;
                    } else if (unsafe { (*(*obj).nodesetval).nodeMax }) <= 40 as i32
                        && ((unsafe { (*cache).nodesetObjs }).is_null()
                            || (unsafe { (*(*cache).nodesetObjs).number }) < (unsafe { (*cache).maxNodeset }))
                    {
                        if (unsafe { (*cache).nodesetObjs }).is_null() {
                            let fresh169 = unsafe { &mut ((*cache).nodesetObjs) };
                            *fresh169 = xmlPointerListCreate(10 as i32);
                            if (unsafe { (*cache).nodesetObjs }).is_null() {
                                current_block = 11237477937609663097;
                            } else {
                                current_block = 10048703153582371463;
                            }
                        } else {
                            current_block = 10048703153582371463;
                        }
                        match current_block {
                            11237477937609663097 => {}
                            _ => {
                                if xmlPointerListAddSize(
                                    unsafe { (*cache).nodesetObjs },
                                    obj as *mut libc::c_void,
                                    0 as i32,
                                ) == -(1 as i32)
                                {
                                    current_block = 11237477937609663097;
                                } else {
                                    current_block = 13108176351440806385;
                                }
                            }
                        }
                    } else {
                        xmlXPathFreeNodeSet(unsafe { (*obj).nodesetval });
                        let fresh170 = unsafe { &mut ((*obj).nodesetval) };
                        *fresh170 = 0 as xmlNodeSetPtr;
                        current_block = 13678349939556791712;
                    }
                } else {
                    current_block = 13678349939556791712;
                }
            }
            4 => {
                if !(unsafe { (*obj).stringval }).is_null() {
                    (unsafe { xmlFree.expect("non-null function pointer")(
                        (*obj).stringval as *mut libc::c_void,
                    ) });
                }
                if (unsafe { (*cache).stringObjs }).is_null()
                    || (unsafe { (*(*cache).stringObjs).number }) < (unsafe { (*cache).maxString })
                {
                    if (unsafe { (*cache).stringObjs }).is_null() {
                        let fresh171 = unsafe { &mut ((*cache).stringObjs) };
                        *fresh171 = xmlPointerListCreate(10 as i32);
                        if (unsafe { (*cache).stringObjs }).is_null() {
                            current_block = 11237477937609663097;
                        } else {
                            current_block = 16924917904204750491;
                        }
                    } else {
                        current_block = 16924917904204750491;
                    }
                    match current_block {
                        11237477937609663097 => {}
                        _ => {
                            if xmlPointerListAddSize(
                                unsafe { (*cache).stringObjs },
                                obj as *mut libc::c_void,
                                0 as i32,
                            ) == -(1 as i32)
                            {
                                current_block = 11237477937609663097;
                            } else {
                                current_block = 13108176351440806385;
                            }
                        }
                    }
                } else {
                    current_block = 13678349939556791712;
                }
            }
            2 => {
                if (unsafe { (*cache).booleanObjs }).is_null()
                    || (unsafe { (*(*cache).booleanObjs).number }) < (unsafe { (*cache).maxBoolean })
                {
                    if (unsafe { (*cache).booleanObjs }).is_null() {
                        let fresh172 = unsafe { &mut ((*cache).booleanObjs) };
                        *fresh172 = xmlPointerListCreate(10 as i32);
                        if (unsafe { (*cache).booleanObjs }).is_null() {
                            current_block = 11237477937609663097;
                        } else {
                            current_block = 11048769245176032998;
                        }
                    } else {
                        current_block = 11048769245176032998;
                    }
                    match current_block {
                        11237477937609663097 => {}
                        _ => {
                            if xmlPointerListAddSize(
                                unsafe { (*cache).booleanObjs },
                                obj as *mut libc::c_void,
                                0 as i32,
                            ) == -(1 as i32)
                            {
                                current_block = 11237477937609663097;
                            } else {
                                current_block = 13108176351440806385;
                            }
                        }
                    }
                } else {
                    current_block = 13678349939556791712;
                }
            }
            3 => {
                if (unsafe { (*cache).numberObjs }).is_null()
                    || (unsafe { (*(*cache).numberObjs).number }) < (unsafe { (*cache).maxNumber })
                {
                    if (unsafe { (*cache).numberObjs }).is_null() {
                        let fresh173 = unsafe { &mut ((*cache).numberObjs) };
                        *fresh173 = xmlPointerListCreate(10 as i32);
                        if (unsafe { (*cache).numberObjs }).is_null() {
                            current_block = 11237477937609663097;
                        } else {
                            current_block = 9441801433784995173;
                        }
                    } else {
                        current_block = 9441801433784995173;
                    }
                    match current_block {
                        11237477937609663097 => {}
                        _ => {
                            if xmlPointerListAddSize(
                                unsafe { (*cache).numberObjs },
                                obj as *mut libc::c_void,
                                0 as i32,
                            ) == -(1 as i32)
                            {
                                current_block = 11237477937609663097;
                            } else {
                                current_block = 13108176351440806385;
                            }
                        }
                    }
                } else {
                    current_block = 13678349939556791712;
                }
            }
            _ => {
                current_block = 11237477937609663097;
            }
        }
        match current_block {
            13678349939556791712 => {
                if (unsafe { (*cache).miscObjs }).is_null() || (unsafe { (*(*cache).miscObjs).number }) < (unsafe { (*cache).maxMisc }) {
                    if (unsafe { (*cache).miscObjs }).is_null() {
                        let fresh174 = unsafe { &mut ((*cache).miscObjs) };
                        *fresh174 = xmlPointerListCreate(10 as i32);
                        if (unsafe { (*cache).miscObjs }).is_null() {
                            current_block = 11237477937609663097;
                        } else {
                            current_block = 1854459640724737493;
                        }
                    } else {
                        current_block = 1854459640724737493;
                    }
                    match current_block {
                        11237477937609663097 => {}
                        _ => {
                            if xmlPointerListAddSize(
                                unsafe { (*cache).miscObjs },
                                obj as *mut libc::c_void,
                                0 as i32,
                            ) == -(1 as i32)
                            {
                                current_block = 11237477937609663097;
                            } else {
                                current_block = 13108176351440806385;
                            }
                        }
                    }
                } else {
                    current_block = 11237477937609663097;
                }
            }
            _ => {}
        }
        match current_block {
            11237477937609663097 => {
                if !(unsafe { (*obj).nodesetval }).is_null() {
                    xmlXPathFreeNodeSet(unsafe { (*obj).nodesetval });
                }
                (unsafe { xmlFree.expect("non-null function pointer")(obj as *mut libc::c_void) });
            }
            _ => {
                if !(unsafe { (*obj).nodesetval }).is_null() {
                    let mut tmpset: xmlNodeSetPtr = unsafe { (*obj).nodesetval };
                    if (unsafe { (*tmpset).nodeNr }) > 1 as i32 {
                        let mut i: i32 = 0;
                        let mut node: xmlNodePtr = 0 as *mut xmlNode;
                        i = 0 as i32;
                        while i < (unsafe { (*tmpset).nodeNr }) {
                            node = unsafe { *((*tmpset).nodeTab).offset(i as isize) };
                            if !node.is_null()
                                && (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
                            {
                                xmlXPathNodeSetFreeNs(node as xmlNsPtr);
                            }
                            i += 1;
                        }
                    } else if (unsafe { (*tmpset).nodeNr }) == 1 as i32 {
                        if !(unsafe { *((*tmpset).nodeTab).offset(0 as i32 as isize) }).is_null()
                            && (unsafe { (**((*tmpset).nodeTab).offset(0 as i32 as isize)).type_0 }) as u32
                                == XML_NAMESPACE_DECL as i32 as u32
                        {
                            xmlXPathNodeSetFreeNs(
                                (unsafe { *((*tmpset).nodeTab).offset(0 as i32 as isize) }) as xmlNsPtr
                            );
                        }
                    }
                    (unsafe { (*tmpset).nodeNr = 0 as i32 });
                    (unsafe { memset(
                        obj as *mut libc::c_void,
                        0 as i32,
                        ::std::mem::size_of::<xmlXPathObject>() as u64,
                    ) });
                    let fresh175 = unsafe { &mut ((*obj).nodesetval) };
                    *fresh175 = tmpset;
                } else {
                    (unsafe { memset(
                        obj as *mut libc::c_void,
                        0 as i32,
                        ::std::mem::size_of::<xmlXPathObject>() as u64,
                    ) });
                }
                return;
            }
        }
    };
}
#[no_mangle]
pub extern "C" fn xmlXPathCastBooleanToString(mut val: i32) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if val != 0 {
        ret = unsafe { xmlStrdup(b"true\0" as *const u8 as *const i8 as *const xmlChar) };
    } else {
        ret = unsafe { xmlStrdup(b"false\0" as *const u8 as *const i8 as *const xmlChar) };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathCastNumberToString(mut val: f64) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    match xmlXPathIsInf(val) {
        1 => {
            ret = unsafe { xmlStrdup(b"Infinity\0" as *const u8 as *const i8 as *const xmlChar) };
        }
        -1 => {
            ret = unsafe { xmlStrdup(b"-Infinity\0" as *const u8 as *const i8 as *const xmlChar) };
        }
        _ => {
            if xmlXPathIsNaN(val) != 0 {
                ret = unsafe { xmlStrdup(b"NaN\0" as *const u8 as *const i8 as *const xmlChar) };
            } else if val == 0 as i32 as f64 {
                ret = unsafe { xmlStrdup(b"0\0" as *const u8 as *const i8 as *const xmlChar) };
            } else {
                let mut buf: [i8; 100] = [0; 100];
                xmlXPathFormatNumber(val, buf.as_mut_ptr(), 99 as i32);
                buf[99 as i32 as usize] = 0 as i32 as i8;
                ret = unsafe { xmlStrdup(buf.as_mut_ptr() as *const xmlChar) };
            }
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathCastNodeToString(mut node: xmlNodePtr) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    ret = unsafe { xmlNodeGetContent(node as *const xmlNode) };
    if ret.is_null() {
        ret = unsafe { xmlStrdup(b"\0" as *const u8 as *const i8 as *const xmlChar) };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathCastNodeSetToString(mut ns: xmlNodeSetPtr) -> *mut xmlChar {
    if ns.is_null() || (unsafe { (*ns).nodeNr }) == 0 as i32 || (unsafe { (*ns).nodeTab }).is_null() {
        return unsafe { xmlStrdup(b"\0" as *const u8 as *const i8 as *const xmlChar) };
    }
    if (unsafe { (*ns).nodeNr }) > 1 as i32 {
        xmlXPathNodeSetSort(ns);
    }
    return xmlXPathCastNodeToString(unsafe { *((*ns).nodeTab).offset(0 as i32 as isize) });
}
#[no_mangle]
pub extern "C" fn xmlXPathCastToString(mut val: xmlXPathObjectPtr) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if val.is_null() {
        return unsafe { xmlStrdup(b"\0" as *const u8 as *const i8 as *const xmlChar) };
    }
    match (unsafe { (*val).type_0 }) as u32 {
        0 => {
            ret = unsafe { xmlStrdup(b"\0" as *const u8 as *const i8 as *const xmlChar) };
        }
        1 | 9 => {
            ret = xmlXPathCastNodeSetToString(unsafe { (*val).nodesetval });
        }
        4 => return unsafe { xmlStrdup((*val).stringval) },
        2 => {
            ret = xmlXPathCastBooleanToString(unsafe { (*val).boolval });
        }
        3 => {
            ret = xmlXPathCastNumberToString(unsafe { (*val).floatval });
        }
        8 => {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                b"xpath.c\0" as *const u8 as *const i8,
                5785 as i32,
            ) });
            ret = unsafe { xmlStrdup(b"\0" as *const u8 as *const i8 as *const xmlChar) };
        }
        _ => {}
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathConvertString(mut val: xmlXPathObjectPtr) -> xmlXPathObjectPtr {
    let mut res: *mut xmlChar = 0 as *mut xmlChar;
    if val.is_null() {
        return xmlXPathNewCString(b"\0" as *const u8 as *const i8);
    }
    match (unsafe { (*val).type_0 }) as u32 {
        1 | 9 => {
            res = xmlXPathCastNodeSetToString(unsafe { (*val).nodesetval });
        }
        4 => return val,
        2 => {
            res = xmlXPathCastBooleanToString(unsafe { (*val).boolval });
        }
        3 => {
            res = xmlXPathCastNumberToString(unsafe { (*val).floatval });
        }
        8 => {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                b"xpath.c\0" as *const u8 as *const i8,
                5832 as i32,
            ) });
        }
        0 | _ => {}
    }
    xmlXPathFreeObject(val);
    if res.is_null() {
        return xmlXPathNewCString(b"\0" as *const u8 as *const i8);
    }
    return xmlXPathWrapString(res);
}
#[no_mangle]
pub extern "C" fn xmlXPathCastBooleanToNumber(mut val: i32) -> f64 {
    if val != 0 {
        return 1.0f64;
    }
    return 0.0f64;
}
#[no_mangle]
pub extern "C" fn xmlXPathCastStringToNumber(mut val: *const xmlChar) -> f64 {
    return xmlXPathStringEvalNumber(val);
}
#[no_mangle]
pub extern "C" fn xmlXPathCastNodeToNumber(mut node: xmlNodePtr) -> f64 {
    let mut strval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ret: f64 = 0.;
    if node.is_null() {
        return unsafe { xmlXPathNAN };
    }
    strval = xmlXPathCastNodeToString(node);
    if strval.is_null() {
        return unsafe { xmlXPathNAN };
    }
    ret = xmlXPathCastStringToNumber(strval);
    (unsafe { xmlFree.expect("non-null function pointer")(strval as *mut libc::c_void) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathCastNodeSetToNumber(mut ns: xmlNodeSetPtr) -> f64 {
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut ret: f64 = 0.;
    if ns.is_null() {
        return unsafe { xmlXPathNAN };
    }
    str = xmlXPathCastNodeSetToString(ns);
    ret = xmlXPathCastStringToNumber(str);
    (unsafe { xmlFree.expect("non-null function pointer")(str as *mut libc::c_void) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathCastToNumber(mut val: xmlXPathObjectPtr) -> f64 {
    let mut ret: f64 = 0.0f64;
    if val.is_null() {
        return unsafe { xmlXPathNAN };
    }
    match (unsafe { (*val).type_0 }) as u32 {
        0 => {
            ret = unsafe { xmlXPathNAN };
        }
        1 | 9 => {
            ret = xmlXPathCastNodeSetToNumber(unsafe { (*val).nodesetval });
        }
        4 => {
            ret = xmlXPathCastStringToNumber(unsafe { (*val).stringval });
        }
        3 => {
            ret = unsafe { (*val).floatval };
        }
        2 => {
            ret = xmlXPathCastBooleanToNumber(unsafe { (*val).boolval });
        }
        8 => {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                b"xpath.c\0" as *const u8 as *const i8,
                5954 as i32,
            ) });
            ret = unsafe { xmlXPathNAN };
        }
        _ => {}
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathConvertNumber(mut val: xmlXPathObjectPtr) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if val.is_null() {
        return xmlXPathNewFloat(0.0f64);
    }
    if (unsafe { (*val).type_0 }) as u32 == XPATH_NUMBER as i32 as u32 {
        return val;
    }
    ret = xmlXPathNewFloat(xmlXPathCastToNumber(val));
    xmlXPathFreeObject(val);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathCastNumberToBoolean(mut val: f64) -> i32 {
    if xmlXPathIsNaN(val) != 0 || val == 0.0f64 {
        return 0 as i32;
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlXPathCastStringToBoolean(mut val: *const xmlChar) -> i32 {
    if val.is_null() || (unsafe { xmlStrlen(val) }) == 0 as i32 {
        return 0 as i32;
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlXPathCastNodeSetToBoolean(mut ns: xmlNodeSetPtr) -> i32 {
    if ns.is_null() || (unsafe { (*ns).nodeNr }) == 0 as i32 {
        return 0 as i32;
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlXPathCastToBoolean(mut val: xmlXPathObjectPtr) -> i32 {
    let mut ret: i32 = 0 as i32;
    if val.is_null() {
        return 0 as i32;
    }
    match (unsafe { (*val).type_0 }) as u32 {
        0 => {
            ret = 0 as i32;
        }
        1 | 9 => {
            ret = xmlXPathCastNodeSetToBoolean(unsafe { (*val).nodesetval });
        }
        4 => {
            ret = xmlXPathCastStringToBoolean(unsafe { (*val).stringval });
        }
        3 => {
            ret = xmlXPathCastNumberToBoolean(unsafe { (*val).floatval });
        }
        2 => {
            ret = unsafe { (*val).boolval };
        }
        8 => {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                b"xpath.c\0" as *const u8 as *const i8,
                6068 as i32,
            ) });
            ret = 0 as i32;
        }
        _ => {}
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathConvertBoolean(mut val: xmlXPathObjectPtr) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if val.is_null() {
        return xmlXPathNewBoolean(0 as i32);
    }
    if (unsafe { (*val).type_0 }) as u32 == XPATH_BOOLEAN as i32 as u32 {
        return val;
    }
    ret = xmlXPathNewBoolean(xmlXPathCastToBoolean(val));
    xmlXPathFreeObject(val);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathNewContext(mut doc: xmlDocPtr) -> xmlXPathContextPtr {
    let mut ret: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathContext>() as u64
    ) }) as xmlXPathContextPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"creating context\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathContextPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathContext>() as u64,
    ) });
    let fresh176 = unsafe { &mut ((*ret).doc) };
    *fresh176 = doc;
    let fresh177 = unsafe { &mut ((*ret).node) };
    *fresh177 = 0 as xmlNodePtr;
    let fresh178 = unsafe { &mut ((*ret).varHash) };
    *fresh178 = 0 as xmlHashTablePtr;
    (unsafe { (*ret).nb_types = 0 as i32 });
    (unsafe { (*ret).max_types = 0 as i32 });
    let fresh179 = unsafe { &mut ((*ret).types) };
    *fresh179 = 0 as xmlXPathTypePtr;
    let fresh180 = unsafe { &mut ((*ret).funcHash) };
    *fresh180 = unsafe { xmlHashCreate(0 as i32) };
    (unsafe { (*ret).nb_axis = 0 as i32 });
    (unsafe { (*ret).max_axis = 0 as i32 });
    let fresh181 = unsafe { &mut ((*ret).axis) };
    *fresh181 = 0 as xmlXPathAxisPtr;
    let fresh182 = unsafe { &mut ((*ret).nsHash) };
    *fresh182 = 0 as xmlHashTablePtr;
    let fresh183 = unsafe { &mut ((*ret).user) };
    *fresh183 = 0 as *mut libc::c_void;
    (unsafe { (*ret).contextSize = -(1 as i32) });
    (unsafe { (*ret).proximityPosition = -(1 as i32) });
    xmlXPathRegisterAllFunctions(ret);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathFreeContext(mut ctxt: xmlXPathContextPtr) {
    if ctxt.is_null() {
        return;
    }
    if !(unsafe { (*ctxt).cache }).is_null() {
        xmlXPathFreeCache((unsafe { (*ctxt).cache }) as xmlXPathContextCachePtr);
    }
    xmlXPathRegisteredNsCleanup(ctxt);
    xmlXPathRegisteredFuncsCleanup(ctxt);
    xmlXPathRegisteredVariablesCleanup(ctxt);
    (unsafe { xmlResetError(&mut (*ctxt).lastError) });
    (unsafe { xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlXPathNewParserContext(
    mut str: *const xmlChar,
    mut ctxt: xmlXPathContextPtr,
) -> xmlXPathParserContextPtr {
    let mut ret: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathParserContext>() as u64,
    ) }) as xmlXPathParserContextPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            ctxt,
            b"creating parser context\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathParserContextPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathParserContext>() as u64,
    ) });
    let fresh184 = unsafe { &mut ((*ret).base) };
    *fresh184 = str;
    let fresh185 = unsafe { &mut ((*ret).cur) };
    *fresh185 = *fresh184;
    let fresh186 = unsafe { &mut ((*ret).context) };
    *fresh186 = ctxt;
    let fresh187 = unsafe { &mut ((*ret).comp) };
    *fresh187 = xmlXPathNewCompExpr();
    if (unsafe { (*ret).comp }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*ret).valueTab as *mut libc::c_void) });
        (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
        return 0 as xmlXPathParserContextPtr;
    }
    if !ctxt.is_null() && !(unsafe { (*ctxt).dict }).is_null() {
        let fresh188 = unsafe { &mut ((*(*ret).comp).dict) };
        *fresh188 = unsafe { (*ctxt).dict };
        (unsafe { xmlDictReference((*(*ret).comp).dict) });
    }
    return ret;
}
extern "C" fn xmlXPathCompParserContext(
    mut comp: xmlXPathCompExprPtr,
    mut ctxt: xmlXPathContextPtr,
) -> xmlXPathParserContextPtr {
    let mut ret: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXPathParserContext>() as u64,
    ) }) as xmlXPathParserContextPtr;
    if ret.is_null() {
        xmlXPathErrMemory(
            ctxt,
            b"creating evaluation context\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathParserContextPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXPathParserContext>() as u64,
    ) });
    let fresh189 = unsafe { &mut ((*ret).valueTab) };
    *fresh189 = (unsafe { xmlMalloc.expect("non-null function pointer")(
        (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlXPathObjectPtr>() as u64),
    ) }) as *mut xmlXPathObjectPtr;
    if (unsafe { (*ret).valueTab }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
        xmlXPathErrMemory(
            ctxt,
            b"creating evaluation context\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlXPathParserContextPtr;
    }
    (unsafe { (*ret).valueNr = 0 as i32 });
    (unsafe { (*ret).valueMax = 10 as i32 });
    let fresh190 = unsafe { &mut ((*ret).value) };
    *fresh190 = 0 as xmlXPathObjectPtr;
    (unsafe { (*ret).valueFrame = 0 as i32 });
    let fresh191 = unsafe { &mut ((*ret).context) };
    *fresh191 = ctxt;
    let fresh192 = unsafe { &mut ((*ret).comp) };
    *fresh192 = comp;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathFreeParserContext(mut ctxt: xmlXPathParserContextPtr) {
    let mut i: i32 = 0;
    if !(unsafe { (*ctxt).valueTab }).is_null() {
        i = 0 as i32;
        while i < (unsafe { (*ctxt).valueNr }) {
            if !(unsafe { (*ctxt).context }).is_null() {
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, unsafe { *((*ctxt).valueTab).offset(i as isize) });
            } else {
                xmlXPathFreeObject(unsafe { *((*ctxt).valueTab).offset(i as isize) });
            }
            i += 1;
        }
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).valueTab as *mut libc::c_void) });
    }
    if !(unsafe { (*ctxt).comp }).is_null() {
        if !(unsafe { (*(*ctxt).comp).stream }).is_null() {
            (unsafe { xmlFreePatternList((*(*ctxt).comp).stream) });
            let fresh193 = unsafe { &mut ((*(*ctxt).comp).stream) };
            *fresh193 = 0 as xmlPatternPtr;
        }
        xmlXPathFreeCompExpr(unsafe { (*ctxt).comp });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void) });
}
extern "C" fn xmlXPathNodeValHash(mut node: xmlNodePtr) -> u32 {
    let mut len: i32 = 2 as i32;
    let mut string: *const xmlChar = 0 as *const xmlChar;
    let mut tmp: xmlNodePtr = 0 as xmlNodePtr;
    let mut ret: u32 = 0 as i32 as u32;
    if node.is_null() {
        return 0 as i32 as u32;
    }
    if (unsafe { (*node).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32 {
        tmp = unsafe { xmlDocGetRootElement(node as xmlDocPtr as *const xmlDoc) };
        if tmp.is_null() {
            node = unsafe { (*node).children };
        } else {
            node = tmp;
        }
        if node.is_null() {
            return 0 as i32 as u32;
        }
    }
    match (unsafe { (*node).type_0 }) as u32 {
        8 | 7 | 4 | 3 => {
            string = unsafe { (*node).content };
            if string.is_null() {
                return 0 as i32 as u32;
            }
            if (unsafe { *string.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
                return 0 as i32 as u32;
            }
            return ((unsafe { *string.offset(0 as i32 as isize) }) as u32)
                .wrapping_add(((unsafe { *string.offset(1 as i32 as isize) }) as u32) << 8 as i32);
        }
        18 => {
            string = unsafe { (*(node as xmlNsPtr)).href };
            if string.is_null() {
                return 0 as i32 as u32;
            }
            if (unsafe { *string.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
                return 0 as i32 as u32;
            }
            return ((unsafe { *string.offset(0 as i32 as isize) }) as u32)
                .wrapping_add(((unsafe { *string.offset(1 as i32 as isize) }) as u32) << 8 as i32);
        }
        2 => {
            tmp = unsafe { (*(node as xmlAttrPtr)).children };
        }
        1 => {
            tmp = unsafe { (*node).children };
        }
        _ => return 0 as i32 as u32,
    }
    while !tmp.is_null() {
        match (unsafe { (*tmp).type_0 }) as u32 {
            4 | 3 => {
                string = unsafe { (*tmp).content };
            }
            _ => {
                string = 0 as *const xmlChar;
            }
        }
        if !string.is_null() && (unsafe { *string.offset(0 as i32 as isize) }) as i32 != 0 as i32 {
            if len == 1 as i32 {
                return ret.wrapping_add(((unsafe { *string.offset(0 as i32 as isize) }) as u32) << 8 as i32);
            }
            if (unsafe { *string.offset(1 as i32 as isize) }) as i32 == 0 as i32 {
                len = 1 as i32;
                ret = (unsafe { *string.offset(0 as i32 as isize) }) as u32;
            } else {
                return ((unsafe { *string.offset(0 as i32 as isize) }) as u32)
                    .wrapping_add(((unsafe { *string.offset(1 as i32 as isize) }) as u32) << 8 as i32);
            }
        }
        if !(unsafe { (*tmp).children }).is_null() && (unsafe { (*tmp).type_0 }) as u32 != XML_DTD_NODE as i32 as u32 {
            if (unsafe { (*(*tmp).children).type_0 }) as u32 != XML_ENTITY_DECL as i32 as u32 {
                tmp = unsafe { (*tmp).children };
                continue;
            }
        }
        if tmp == node {
            break;
        }
        if !(unsafe { (*tmp).next }).is_null() {
            tmp = unsafe { (*tmp).next };
        } else {
            loop {
                tmp = unsafe { (*tmp).parent };
                if tmp.is_null() {
                    break;
                }
                if tmp == node {
                    tmp = 0 as xmlNodePtr;
                    break;
                } else if !(unsafe { (*tmp).next }).is_null() {
                    tmp = unsafe { (*tmp).next };
                    break;
                } else if tmp.is_null() {
                    break;
                }
            }
        }
    }
    return ret;
}
extern "C" fn xmlXPathStringHash(mut string: *const xmlChar) -> u32 {
    if string.is_null() {
        return 0 as i32 as u32;
    }
    if (unsafe { *string.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
        return 0 as i32 as u32;
    }
    return ((unsafe { *string.offset(0 as i32 as isize) }) as u32)
        .wrapping_add(((unsafe { *string.offset(1 as i32 as isize) }) as u32) << 8 as i32);
}
extern "C" fn xmlXPathCompareNodeSetFloat(
    mut ctxt: xmlXPathParserContextPtr,
    mut inf: i32,
    mut strict: i32,
    mut arg: xmlXPathObjectPtr,
    mut f: xmlXPathObjectPtr,
) -> i32 {
    let mut i: i32 = 0;
    let mut ret: i32 = 0 as i32;
    let mut ns: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    if f.is_null()
        || arg.is_null()
        || (unsafe { (*arg).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*arg).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg);
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, f);
        return 0 as i32;
    }
    ns = unsafe { (*arg).nodesetval };
    if !ns.is_null() {
        i = 0 as i32;
        while i < (unsafe { (*ns).nodeNr }) {
            str2 = xmlXPathCastNodeToString(unsafe { *((*ns).nodeTab).offset(i as isize) });
            if !str2.is_null() {
                valuePush(ctxt, xmlXPathCacheNewString(unsafe { (*ctxt).context }, str2));
                (unsafe { xmlFree.expect("non-null function pointer")(str2 as *mut libc::c_void) });
                xmlXPathNumberFunction(ctxt, 1 as i32);
                valuePush(ctxt, xmlXPathCacheObjectCopy(unsafe { (*ctxt).context }, f));
                ret = xmlXPathCompareValues(ctxt, inf, strict);
                if ret != 0 {
                    break;
                }
            }
            i += 1;
        }
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, f);
    return ret;
}
extern "C" fn xmlXPathCompareNodeSetString(
    mut ctxt: xmlXPathParserContextPtr,
    mut inf: i32,
    mut strict: i32,
    mut arg: xmlXPathObjectPtr,
    mut s: xmlXPathObjectPtr,
) -> i32 {
    let mut i: i32 = 0;
    let mut ret: i32 = 0 as i32;
    let mut ns: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    if s.is_null()
        || arg.is_null()
        || (unsafe { (*arg).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*arg).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg);
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, s);
        return 0 as i32;
    }
    ns = unsafe { (*arg).nodesetval };
    if !ns.is_null() {
        i = 0 as i32;
        while i < (unsafe { (*ns).nodeNr }) {
            str2 = xmlXPathCastNodeToString(unsafe { *((*ns).nodeTab).offset(i as isize) });
            if !str2.is_null() {
                valuePush(ctxt, xmlXPathCacheNewString(unsafe { (*ctxt).context }, str2));
                (unsafe { xmlFree.expect("non-null function pointer")(str2 as *mut libc::c_void) });
                valuePush(ctxt, xmlXPathCacheObjectCopy(unsafe { (*ctxt).context }, s));
                ret = xmlXPathCompareValues(ctxt, inf, strict);
                if ret != 0 {
                    break;
                }
            }
            i += 1;
        }
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, s);
    return ret;
}
extern "C" fn xmlXPathCompareNodeSets(
    mut inf: i32,
    mut strict: i32,
    mut arg1: xmlXPathObjectPtr,
    mut arg2: xmlXPathObjectPtr,
) -> i32 {
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    let mut init: i32 = 0 as i32;
    let mut val1: f64 = 0.;
    let mut values2: *mut f64 = 0 as *mut f64;
    let mut ret: i32 = 0 as i32;
    let mut ns1: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut ns2: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    if arg1.is_null()
        || (unsafe { (*arg1).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*arg1).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        xmlXPathFreeObject(arg2);
        return 0 as i32;
    }
    if arg2.is_null()
        || (unsafe { (*arg2).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*arg2).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        xmlXPathFreeObject(arg1);
        xmlXPathFreeObject(arg2);
        return 0 as i32;
    }
    ns1 = unsafe { (*arg1).nodesetval };
    ns2 = unsafe { (*arg2).nodesetval };
    if ns1.is_null() || (unsafe { (*ns1).nodeNr }) <= 0 as i32 {
        xmlXPathFreeObject(arg1);
        xmlXPathFreeObject(arg2);
        return 0 as i32;
    }
    if ns2.is_null() || (unsafe { (*ns2).nodeNr }) <= 0 as i32 {
        xmlXPathFreeObject(arg1);
        xmlXPathFreeObject(arg2);
        return 0 as i32;
    }
    values2 = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ((*ns2).nodeNr as u64).wrapping_mul(::std::mem::size_of::<f64>() as u64),
    ) }) as *mut f64;
    if values2.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"comparing nodesets\n\0" as *const u8 as *const i8,
        );
        xmlXPathFreeObject(arg1);
        xmlXPathFreeObject(arg2);
        return 0 as i32;
    }
    i = 0 as i32;
    while i < (unsafe { (*ns1).nodeNr }) {
        val1 = xmlXPathCastNodeToNumber(unsafe { *((*ns1).nodeTab).offset(i as isize) });
        if !(xmlXPathIsNaN(val1) != 0) {
            j = 0 as i32;
            while j < (unsafe { (*ns2).nodeNr }) {
                if init == 0 as i32 {
                    (unsafe { *values2.offset(j as isize) =
                        xmlXPathCastNodeToNumber(*((*ns2).nodeTab).offset(j as isize)) });
                }
                if !(xmlXPathIsNaN(unsafe { *values2.offset(j as isize) }) != 0) {
                    if inf != 0 && strict != 0 {
                        ret = (val1 < (unsafe { *values2.offset(j as isize) })) as i32;
                    } else if inf != 0 && strict == 0 {
                        ret = (val1 <= (unsafe { *values2.offset(j as isize) })) as i32;
                    } else if inf == 0 && strict != 0 {
                        ret = (val1 > (unsafe { *values2.offset(j as isize) })) as i32;
                    } else if inf == 0 && strict == 0 {
                        ret = (val1 >= (unsafe { *values2.offset(j as isize) })) as i32;
                    }
                    if ret != 0 {
                        break;
                    }
                }
                j += 1;
            }
            if ret != 0 {
                break;
            }
            init = 1 as i32;
        }
        i += 1;
    }
    (unsafe { xmlFree.expect("non-null function pointer")(values2 as *mut libc::c_void) });
    xmlXPathFreeObject(arg1);
    xmlXPathFreeObject(arg2);
    return ret;
}
extern "C" fn xmlXPathCompareNodeSetValue(
    mut ctxt: xmlXPathParserContextPtr,
    mut inf: i32,
    mut strict: i32,
    mut arg: xmlXPathObjectPtr,
    mut val: xmlXPathObjectPtr,
) -> i32 {
    if val.is_null()
        || arg.is_null()
        || (unsafe { (*arg).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*arg).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        return 0 as i32;
    }
    match (unsafe { (*val).type_0 }) as u32 {
        3 => return xmlXPathCompareNodeSetFloat(ctxt, inf, strict, arg, val),
        1 | 9 => return xmlXPathCompareNodeSets(inf, strict, arg, val),
        4 => return xmlXPathCompareNodeSetString(ctxt, inf, strict, arg, val),
        2 => {
            valuePush(ctxt, arg);
            xmlXPathBooleanFunction(ctxt, 1 as i32);
            valuePush(ctxt, val);
            return xmlXPathCompareValues(ctxt, inf, strict);
        }
        _ => {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlXPathCompareNodeSetValue: Can't compare node set and object of type %d\n\0"
                    as *const u8 as *const i8,
                (*val).type_0 as u32,
            ) });
            xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg);
            xmlXPathReleaseObject(unsafe { (*ctxt).context }, val);
            xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
            return 0 as i32;
        }
    };
}
extern "C" fn xmlXPathEqualNodeSetString(
    mut arg: xmlXPathObjectPtr,
    mut str: *const xmlChar,
    mut neq: i32,
) -> i32 {
    let mut i: i32 = 0;
    let mut ns: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    let mut hash: u32 = 0;
    if str.is_null()
        || arg.is_null()
        || (unsafe { (*arg).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*arg).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        return 0 as i32;
    }
    ns = unsafe { (*arg).nodesetval };
    if ns.is_null() || (unsafe { (*ns).nodeNr }) <= 0 as i32 {
        return 0 as i32;
    }
    hash = xmlXPathStringHash(str);
    i = 0 as i32;
    while i < (unsafe { (*ns).nodeNr }) {
        if xmlXPathNodeValHash(unsafe { *((*ns).nodeTab).offset(i as isize) }) == hash {
            str2 = unsafe { xmlNodeGetContent(*((*ns).nodeTab).offset(i as isize) as *const xmlNode) };
            if !str2.is_null() && (unsafe { xmlStrEqual(str, str2) }) != 0 {
                (unsafe { xmlFree.expect("non-null function pointer")(str2 as *mut libc::c_void) });
                if !(neq != 0) {
                    return 1 as i32;
                }
            } else if str2.is_null()
                && (unsafe { xmlStrEqual(str, b"\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0
            {
                if !(neq != 0) {
                    return 1 as i32;
                }
            } else {
                if neq != 0 {
                    if !str2.is_null() {
                        (unsafe { xmlFree.expect("non-null function pointer")(str2 as *mut libc::c_void) });
                    }
                    return 1 as i32;
                }
                if !str2.is_null() {
                    (unsafe { xmlFree.expect("non-null function pointer")(str2 as *mut libc::c_void) });
                }
            }
        } else if neq != 0 {
            return 1 as i32;
        }
        i += 1;
    }
    return 0 as i32;
}
extern "C" fn xmlXPathEqualNodeSetFloat(
    mut ctxt: xmlXPathParserContextPtr,
    mut arg: xmlXPathObjectPtr,
    mut f: f64,
    mut neq: i32,
) -> i32 {
    let mut i: i32 = 0;
    let mut ret: i32 = 0 as i32;
    let mut ns: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut v: f64 = 0.;
    if arg.is_null()
        || (unsafe { (*arg).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*arg).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        return 0 as i32;
    }
    ns = unsafe { (*arg).nodesetval };
    if !ns.is_null() {
        i = 0 as i32;
        while i < (unsafe { (*ns).nodeNr }) {
            str2 = xmlXPathCastNodeToString(unsafe { *((*ns).nodeTab).offset(i as isize) });
            if !str2.is_null() {
                valuePush(ctxt, xmlXPathCacheNewString(unsafe { (*ctxt).context }, str2));
                (unsafe { xmlFree.expect("non-null function pointer")(str2 as *mut libc::c_void) });
                xmlXPathNumberFunction(ctxt, 1 as i32);
                val = valuePop(ctxt);
                v = unsafe { (*val).floatval };
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, val);
                if xmlXPathIsNaN(v) == 0 {
                    if neq == 0 && v == f {
                        ret = 1 as i32;
                        break;
                    } else if neq != 0 && v != f {
                        ret = 1 as i32;
                        break;
                    }
                } else if neq != 0 {
                    ret = 1 as i32;
                }
            }
            i += 1;
        }
    }
    return ret;
}
extern "C" fn xmlXPathEqualNodeSets(
    mut arg1: xmlXPathObjectPtr,
    mut arg2: xmlXPathObjectPtr,
    mut neq: i32,
) -> i32 {
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    let mut hashs1: *mut u32 = 0 as *mut u32;
    let mut hashs2: *mut u32 = 0 as *mut u32;
    let mut values1: *mut *mut xmlChar = 0 as *mut *mut xmlChar;
    let mut values2: *mut *mut xmlChar = 0 as *mut *mut xmlChar;
    let mut ret: i32 = 0 as i32;
    let mut ns1: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut ns2: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    if arg1.is_null()
        || (unsafe { (*arg1).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*arg1).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        return 0 as i32;
    }
    if arg2.is_null()
        || (unsafe { (*arg2).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*arg2).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        return 0 as i32;
    }
    ns1 = unsafe { (*arg1).nodesetval };
    ns2 = unsafe { (*arg2).nodesetval };
    if ns1.is_null() || (unsafe { (*ns1).nodeNr }) <= 0 as i32 {
        return 0 as i32;
    }
    if ns2.is_null() || (unsafe { (*ns2).nodeNr }) <= 0 as i32 {
        return 0 as i32;
    }
    if neq == 0 as i32 {
        i = 0 as i32;
        while i < (unsafe { (*ns1).nodeNr }) {
            j = 0 as i32;
            while j < (unsafe { (*ns2).nodeNr }) {
                if (unsafe { *((*ns1).nodeTab).offset(i as isize) }) == (unsafe { *((*ns2).nodeTab).offset(j as isize) }) {
                    return 1 as i32;
                }
                j += 1;
            }
            i += 1;
        }
    }
    values1 = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ((*ns1).nodeNr as u64).wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
    ) }) as *mut *mut xmlChar;
    if values1.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"comparing nodesets\n\0" as *const u8 as *const i8,
        );
        return 0 as i32;
    }
    hashs1 = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ((*ns1).nodeNr as u64).wrapping_mul(::std::mem::size_of::<u32>() as u64),
    ) }) as *mut u32;
    if hashs1.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"comparing nodesets\n\0" as *const u8 as *const i8,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(values1 as *mut libc::c_void) });
        return 0 as i32;
    }
    (unsafe { memset(
        values1 as *mut libc::c_void,
        0 as i32,
        ((*ns1).nodeNr as u64).wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
    ) });
    values2 = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ((*ns2).nodeNr as u64).wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
    ) }) as *mut *mut xmlChar;
    if values2.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"comparing nodesets\n\0" as *const u8 as *const i8,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(hashs1 as *mut libc::c_void) });
        (unsafe { xmlFree.expect("non-null function pointer")(values1 as *mut libc::c_void) });
        return 0 as i32;
    }
    hashs2 = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ((*ns2).nodeNr as u64).wrapping_mul(::std::mem::size_of::<u32>() as u64),
    ) }) as *mut u32;
    if hashs2.is_null() {
        xmlXPathErrMemory(
            0 as xmlXPathContextPtr,
            b"comparing nodesets\n\0" as *const u8 as *const i8,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(hashs1 as *mut libc::c_void) });
        (unsafe { xmlFree.expect("non-null function pointer")(values1 as *mut libc::c_void) });
        (unsafe { xmlFree.expect("non-null function pointer")(values2 as *mut libc::c_void) });
        return 0 as i32;
    }
    (unsafe { memset(
        values2 as *mut libc::c_void,
        0 as i32,
        ((*ns2).nodeNr as u64).wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
    ) });
    i = 0 as i32;
    while i < (unsafe { (*ns1).nodeNr }) {
        (unsafe { *hashs1.offset(i as isize) = xmlXPathNodeValHash(*((*ns1).nodeTab).offset(i as isize)) });
        j = 0 as i32;
        while j < (unsafe { (*ns2).nodeNr }) {
            if i == 0 as i32 {
                (unsafe { *hashs2.offset(j as isize) =
                    xmlXPathNodeValHash(*((*ns2).nodeTab).offset(j as isize)) });
            }
            if (unsafe { *hashs1.offset(i as isize) }) != (unsafe { *hashs2.offset(j as isize) }) {
                if neq != 0 {
                    ret = 1 as i32;
                    break;
                }
            } else {
                if (unsafe { *values1.offset(i as isize) }).is_null() {
                    let fresh194 = unsafe { &mut (*values1.offset(i as isize)) };
                    *fresh194 =
                        unsafe { xmlNodeGetContent(*((*ns1).nodeTab).offset(i as isize) as *const xmlNode) };
                }
                if (unsafe { *values2.offset(j as isize) }).is_null() {
                    let fresh195 = unsafe { &mut (*values2.offset(j as isize)) };
                    *fresh195 =
                        unsafe { xmlNodeGetContent(*((*ns2).nodeTab).offset(j as isize) as *const xmlNode) };
                }
                ret = (unsafe { xmlStrEqual(*values1.offset(i as isize), *values2.offset(j as isize)) }) ^ neq;
                if ret != 0 {
                    break;
                }
            }
            j += 1;
        }
        if ret != 0 {
            break;
        }
        i += 1;
    }
    i = 0 as i32;
    while i < (unsafe { (*ns1).nodeNr }) {
        if !(unsafe { *values1.offset(i as isize) }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(
                *values1.offset(i as isize) as *mut libc::c_void
            ) });
        }
        i += 1;
    }
    j = 0 as i32;
    while j < (unsafe { (*ns2).nodeNr }) {
        if !(unsafe { *values2.offset(j as isize) }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(
                *values2.offset(j as isize) as *mut libc::c_void
            ) });
        }
        j += 1;
    }
    (unsafe { xmlFree.expect("non-null function pointer")(values1 as *mut libc::c_void) });
    (unsafe { xmlFree.expect("non-null function pointer")(values2 as *mut libc::c_void) });
    (unsafe { xmlFree.expect("non-null function pointer")(hashs1 as *mut libc::c_void) });
    (unsafe { xmlFree.expect("non-null function pointer")(hashs2 as *mut libc::c_void) });
    return ret;
}
extern "C" fn xmlXPathEqualValuesCommon(
    mut ctxt: xmlXPathParserContextPtr,
    mut arg1: xmlXPathObjectPtr,
    mut arg2: xmlXPathObjectPtr,
) -> i32 {
    let mut ret: i32 = 0 as i32;
    match (unsafe { (*arg1).type_0 }) as u32 {
        2 => match (unsafe { (*arg2).type_0 }) as u32 {
            2 => {
                ret = ((unsafe { (*arg1).boolval }) == (unsafe { (*arg2).boolval })) as i32;
            }
            3 => {
                ret = ((unsafe { (*arg1).boolval }) == xmlXPathCastNumberToBoolean(unsafe { (*arg2).floatval })) as i32;
            }
            4 => {
                if (unsafe { (*arg2).stringval }).is_null()
                    || (unsafe { *((*arg2).stringval).offset(0 as i32 as isize) }) as i32 == 0 as i32
                {
                    ret = 0 as i32;
                } else {
                    ret = 1 as i32;
                }
                ret = ((unsafe { (*arg1).boolval }) == ret) as i32;
            }
            8 => {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                    b"xpath.c\0" as *const u8 as *const i8,
                    7009 as i32,
                ) });
            }
            0 | 1 | 9 | _ => {}
        },
        3 => {
            let mut current_block_37: u64;
            match (unsafe { (*arg2).type_0 }) as u32 {
                2 => {
                    ret = ((unsafe { (*arg2).boolval }) == xmlXPathCastNumberToBoolean(unsafe { (*arg1).floatval })) as i32;
                    current_block_37 = 6174974146017752131;
                }
                4 => {
                    valuePush(ctxt, arg2);
                    xmlXPathNumberFunction(ctxt, 1 as i32);
                    arg2 = valuePop(ctxt);
                    current_block_37 = 14983914821605129355;
                }
                3 => {
                    current_block_37 = 14983914821605129355;
                }
                8 => {
                    (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                        b"xpath.c\0" as *const u8 as *const i8,
                        7068 as i32,
                    ) });
                    current_block_37 = 6174974146017752131;
                }
                0 | 1 | 9 | _ => {
                    current_block_37 = 6174974146017752131;
                }
            }
            match current_block_37 {
                14983914821605129355 => {
                    if xmlXPathIsNaN(unsafe { (*arg1).floatval }) != 0 || xmlXPathIsNaN(unsafe { (*arg2).floatval }) != 0
                    {
                        ret = 0 as i32;
                    } else if xmlXPathIsInf(unsafe { (*arg1).floatval }) == 1 as i32 {
                        if xmlXPathIsInf(unsafe { (*arg2).floatval }) == 1 as i32 {
                            ret = 1 as i32;
                        } else {
                            ret = 0 as i32;
                        }
                    } else if xmlXPathIsInf(unsafe { (*arg1).floatval }) == -(1 as i32) {
                        if xmlXPathIsInf(unsafe { (*arg2).floatval }) == -(1 as i32) {
                            ret = 1 as i32;
                        } else {
                            ret = 0 as i32;
                        }
                    } else if xmlXPathIsInf(unsafe { (*arg2).floatval }) == 1 as i32 {
                        if xmlXPathIsInf(unsafe { (*arg1).floatval }) == 1 as i32 {
                            ret = 1 as i32;
                        } else {
                            ret = 0 as i32;
                        }
                    } else if xmlXPathIsInf(unsafe { (*arg2).floatval }) == -(1 as i32) {
                        if xmlXPathIsInf(unsafe { (*arg1).floatval }) == -(1 as i32) {
                            ret = 1 as i32;
                        } else {
                            ret = 0 as i32;
                        }
                    } else {
                        ret = ((unsafe { (*arg1).floatval }) == (unsafe { (*arg2).floatval })) as i32;
                    }
                }
                _ => {}
            }
        }
        4 => match (unsafe { (*arg2).type_0 }) as u32 {
            2 => {
                if (unsafe { (*arg1).stringval }).is_null()
                    || (unsafe { *((*arg1).stringval).offset(0 as i32 as isize) }) as i32 == 0 as i32
                {
                    ret = 0 as i32;
                } else {
                    ret = 1 as i32;
                }
                ret = ((unsafe { (*arg2).boolval }) == ret) as i32;
            }
            4 => {
                ret = unsafe { xmlStrEqual((*arg1).stringval, (*arg2).stringval) };
            }
            3 => {
                valuePush(ctxt, arg1);
                xmlXPathNumberFunction(ctxt, 1 as i32);
                arg1 = valuePop(ctxt);
                if xmlXPathIsNaN(unsafe { (*arg1).floatval }) != 0 || xmlXPathIsNaN(unsafe { (*arg2).floatval }) != 0 {
                    ret = 0 as i32;
                } else if xmlXPathIsInf(unsafe { (*arg1).floatval }) == 1 as i32 {
                    if xmlXPathIsInf(unsafe { (*arg2).floatval }) == 1 as i32 {
                        ret = 1 as i32;
                    } else {
                        ret = 0 as i32;
                    }
                } else if xmlXPathIsInf(unsafe { (*arg1).floatval }) == -(1 as i32) {
                    if xmlXPathIsInf(unsafe { (*arg2).floatval }) == -(1 as i32) {
                        ret = 1 as i32;
                    } else {
                        ret = 0 as i32;
                    }
                } else if xmlXPathIsInf(unsafe { (*arg2).floatval }) == 1 as i32 {
                    if xmlXPathIsInf(unsafe { (*arg1).floatval }) == 1 as i32 {
                        ret = 1 as i32;
                    } else {
                        ret = 0 as i32;
                    }
                } else if xmlXPathIsInf(unsafe { (*arg2).floatval }) == -(1 as i32) {
                    if xmlXPathIsInf(unsafe { (*arg1).floatval }) == -(1 as i32) {
                        ret = 1 as i32;
                    } else {
                        ret = 0 as i32;
                    }
                } else {
                    ret = ((unsafe { (*arg1).floatval }) == (unsafe { (*arg2).floatval })) as i32;
                }
            }
            8 => {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                    b"xpath.c\0" as *const u8 as *const i8,
                    7131 as i32,
                ) });
            }
            0 | 1 | 9 | _ => {}
        },
        8 => {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                b"xpath.c\0" as *const u8 as *const i8,
                7144 as i32,
            ) });
        }
        0 | 1 | 9 | _ => {}
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathEqualValues(mut ctxt: xmlXPathParserContextPtr) -> i32 {
    let mut arg1: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut arg2: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut argtmp: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut ret: i32 = 0 as i32;
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as i32;
    }
    arg2 = valuePop(ctxt);
    arg1 = valuePop(ctxt);
    if arg1.is_null() || arg2.is_null() {
        if !arg1.is_null() {
            xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
        } else {
            xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
        }
        xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
        return 0 as i32;
    }
    if arg1 == arg2 {
        xmlXPathFreeObject(arg1);
        return 1 as i32;
    }
    if (unsafe { (*arg2).type_0 }) as u32 == XPATH_NODESET as i32 as u32
        || (unsafe { (*arg2).type_0 }) as u32 == XPATH_XSLT_TREE as i32 as u32
        || (unsafe { (*arg1).type_0 }) as u32 == XPATH_NODESET as i32 as u32
        || (unsafe { (*arg1).type_0 }) as u32 == XPATH_XSLT_TREE as i32 as u32
    {
        if (unsafe { (*arg1).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*arg1).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
        {
            argtmp = arg2;
            arg2 = arg1;
            arg1 = argtmp;
        }
        match (unsafe { (*arg2).type_0 }) as u32 {
            1 | 9 => {
                ret = xmlXPathEqualNodeSets(arg1, arg2, 0 as i32);
            }
            2 => {
                if (unsafe { (*arg1).nodesetval }).is_null() || (unsafe { (*(*arg1).nodesetval).nodeNr }) == 0 as i32 {
                    ret = 0 as i32;
                } else {
                    ret = 1 as i32;
                }
                ret = (ret == (unsafe { (*arg2).boolval })) as i32;
            }
            3 => {
                ret = xmlXPathEqualNodeSetFloat(ctxt, arg1, unsafe { (*arg2).floatval }, 0 as i32);
            }
            4 => {
                ret = xmlXPathEqualNodeSetString(arg1, unsafe { (*arg2).stringval }, 0 as i32);
            }
            8 => {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                    b"xpath.c\0" as *const u8 as *const i8,
                    7231 as i32,
                ) });
            }
            0 | _ => {}
        }
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
        return ret;
    }
    return xmlXPathEqualValuesCommon(ctxt, arg1, arg2);
}
#[no_mangle]
pub extern "C" fn xmlXPathNotEqualValues(mut ctxt: xmlXPathParserContextPtr) -> i32 {
    let mut arg1: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut arg2: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut argtmp: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut ret: i32 = 0 as i32;
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as i32;
    }
    arg2 = valuePop(ctxt);
    arg1 = valuePop(ctxt);
    if arg1.is_null() || arg2.is_null() {
        if !arg1.is_null() {
            xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
        } else {
            xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
        }
        xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
        return 0 as i32;
    }
    if arg1 == arg2 {
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
        return 0 as i32;
    }
    if (unsafe { (*arg2).type_0 }) as u32 == XPATH_NODESET as i32 as u32
        || (unsafe { (*arg2).type_0 }) as u32 == XPATH_XSLT_TREE as i32 as u32
        || (unsafe { (*arg1).type_0 }) as u32 == XPATH_NODESET as i32 as u32
        || (unsafe { (*arg1).type_0 }) as u32 == XPATH_XSLT_TREE as i32 as u32
    {
        if (unsafe { (*arg1).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*arg1).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
        {
            argtmp = arg2;
            arg2 = arg1;
            arg1 = argtmp;
        }
        match (unsafe { (*arg2).type_0 }) as u32 {
            1 | 9 => {
                ret = xmlXPathEqualNodeSets(arg1, arg2, 1 as i32);
            }
            2 => {
                if (unsafe { (*arg1).nodesetval }).is_null() || (unsafe { (*(*arg1).nodesetval).nodeNr }) == 0 as i32 {
                    ret = 0 as i32;
                } else {
                    ret = 1 as i32;
                }
                ret = (ret != (unsafe { (*arg2).boolval })) as i32;
            }
            3 => {
                ret = xmlXPathEqualNodeSetFloat(ctxt, arg1, unsafe { (*arg2).floatval }, 1 as i32);
            }
            4 => {
                ret = xmlXPathEqualNodeSetString(arg1, unsafe { (*arg2).stringval }, 1 as i32);
            }
            8 => {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                    b"xpath.c\0" as *const u8 as *const i8,
                    7318 as i32,
                ) });
            }
            0 | _ => {}
        }
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
        return ret;
    }
    return (xmlXPathEqualValuesCommon(ctxt, arg1, arg2) == 0) as i32;
}
#[no_mangle]
pub extern "C" fn xmlXPathCompareValues(
    mut ctxt: xmlXPathParserContextPtr,
    mut inf: i32,
    mut strict: i32,
) -> i32 {
    let mut ret: i32 = 0 as i32;
    let mut arg1i: i32 = 0 as i32;
    let mut arg2i: i32 = 0 as i32;
    let mut arg1: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut arg2: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as i32;
    }
    arg2 = valuePop(ctxt);
    arg1 = valuePop(ctxt);
    if arg1.is_null() || arg2.is_null() {
        if !arg1.is_null() {
            xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
        } else {
            xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
        }
        xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
        return 0 as i32;
    }
    if (unsafe { (*arg2).type_0 }) as u32 == XPATH_NODESET as i32 as u32
        || (unsafe { (*arg2).type_0 }) as u32 == XPATH_XSLT_TREE as i32 as u32
        || (unsafe { (*arg1).type_0 }) as u32 == XPATH_NODESET as i32 as u32
        || (unsafe { (*arg1).type_0 }) as u32 == XPATH_XSLT_TREE as i32 as u32
    {
        if ((unsafe { (*arg2).type_0 }) as u32 == XPATH_NODESET as i32 as u32
            || (unsafe { (*arg2).type_0 }) as u32 == XPATH_XSLT_TREE as i32 as u32)
            && ((unsafe { (*arg1).type_0 }) as u32 == XPATH_NODESET as i32 as u32
                || (unsafe { (*arg1).type_0 }) as u32 == XPATH_XSLT_TREE as i32 as u32)
        {
            ret = xmlXPathCompareNodeSets(inf, strict, arg1, arg2);
        } else if (unsafe { (*arg1).type_0 }) as u32 == XPATH_NODESET as i32 as u32
            || (unsafe { (*arg1).type_0 }) as u32 == XPATH_XSLT_TREE as i32 as u32
        {
            ret = xmlXPathCompareNodeSetValue(ctxt, inf, strict, arg1, arg2);
        } else {
            ret = xmlXPathCompareNodeSetValue(ctxt, (inf == 0) as i32, strict, arg2, arg1);
        }
        return ret;
    }
    if (unsafe { (*arg1).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        valuePush(ctxt, arg1);
        xmlXPathNumberFunction(ctxt, 1 as i32);
        arg1 = valuePop(ctxt);
    }
    if (unsafe { (*arg1).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathFreeObject(arg1);
        xmlXPathFreeObject(arg2);
        xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
        return 0 as i32;
    }
    if (unsafe { (*arg2).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        valuePush(ctxt, arg2);
        xmlXPathNumberFunction(ctxt, 1 as i32);
        arg2 = valuePop(ctxt);
    }
    if (unsafe { (*arg2).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
        xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
        return 0 as i32;
    }
    if xmlXPathIsNaN(unsafe { (*arg1).floatval }) != 0 || xmlXPathIsNaN(unsafe { (*arg2).floatval }) != 0 {
        ret = 0 as i32;
    } else {
        arg1i = xmlXPathIsInf(unsafe { (*arg1).floatval });
        arg2i = xmlXPathIsInf(unsafe { (*arg2).floatval });
        if inf != 0 && strict != 0 {
            if arg1i == -(1 as i32) && arg2i != -(1 as i32)
                || arg2i == 1 as i32 && arg1i != 1 as i32
            {
                ret = 1 as i32;
            } else if arg1i == 0 as i32 && arg2i == 0 as i32 {
                ret = ((unsafe { (*arg1).floatval }) < (unsafe { (*arg2).floatval })) as i32;
            } else {
                ret = 0 as i32;
            }
        } else if inf != 0 && strict == 0 {
            if arg1i == -(1 as i32) || arg2i == 1 as i32 {
                ret = 1 as i32;
            } else if arg1i == 0 as i32 && arg2i == 0 as i32 {
                ret = ((unsafe { (*arg1).floatval }) <= (unsafe { (*arg2).floatval })) as i32;
            } else {
                ret = 0 as i32;
            }
        } else if inf == 0 && strict != 0 {
            if arg1i == 1 as i32 && arg2i != 1 as i32
                || arg2i == -(1 as i32) && arg1i != -(1 as i32)
            {
                ret = 1 as i32;
            } else if arg1i == 0 as i32 && arg2i == 0 as i32 {
                ret = ((unsafe { (*arg1).floatval }) > (unsafe { (*arg2).floatval })) as i32;
            } else {
                ret = 0 as i32;
            }
        } else if inf == 0 && strict == 0 {
            if arg1i == 1 as i32 || arg2i == -(1 as i32) {
                ret = 1 as i32;
            } else if arg1i == 0 as i32 && arg2i == 0 as i32 {
                ret = ((unsafe { (*arg1).floatval }) >= (unsafe { (*arg2).floatval })) as i32;
            } else {
                ret = 0 as i32;
            }
        }
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathValueFlipSign(mut ctxt: xmlXPathParserContextPtr) {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return;
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathNumberFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    (unsafe { (*(*ctxt).value).floatval = -(*(*ctxt).value).floatval });
}
#[no_mangle]
pub extern "C" fn xmlXPathAddValues(mut ctxt: xmlXPathParserContextPtr) {
    let mut arg: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: f64 = 0.;
    arg = valuePop(ctxt);
    if arg.is_null() {
        xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
        return;
    }
    val = xmlXPathCastToNumber(arg);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg);
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathNumberFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    (unsafe { (*(*ctxt).value).floatval += val });
}
#[no_mangle]
pub extern "C" fn xmlXPathSubValues(mut ctxt: xmlXPathParserContextPtr) {
    let mut arg: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: f64 = 0.;
    arg = valuePop(ctxt);
    if arg.is_null() {
        xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
        return;
    }
    val = xmlXPathCastToNumber(arg);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg);
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathNumberFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    (unsafe { (*(*ctxt).value).floatval -= val });
}
#[no_mangle]
pub extern "C" fn xmlXPathMultValues(mut ctxt: xmlXPathParserContextPtr) {
    let mut arg: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: f64 = 0.;
    arg = valuePop(ctxt);
    if arg.is_null() {
        xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
        return;
    }
    val = xmlXPathCastToNumber(arg);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg);
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathNumberFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    (unsafe { (*(*ctxt).value).floatval *= val });
}
#[no_mangle]
pub extern "C" fn xmlXPathDivValues(mut ctxt: xmlXPathParserContextPtr) {
    let mut arg: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: f64 = 0.;
    arg = valuePop(ctxt);
    if arg.is_null() {
        xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
        return;
    }
    val = xmlXPathCastToNumber(arg);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg);
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathNumberFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    (unsafe { (*(*ctxt).value).floatval /= val });
}
#[no_mangle]
pub extern "C" fn xmlXPathModValues(mut ctxt: xmlXPathParserContextPtr) {
    let mut arg: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut arg1: f64 = 0.;
    let mut arg2: f64 = 0.;
    arg = valuePop(ctxt);
    if arg.is_null() {
        xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
        return;
    }
    arg2 = xmlXPathCastToNumber(arg);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg);
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathNumberFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    arg1 = unsafe { (*(*ctxt).value).floatval };
    if arg2 == 0 as i32 as f64 {
        (unsafe { (*(*ctxt).value).floatval = xmlXPathNAN });
    } else {
        (unsafe { (*(*ctxt).value).floatval = fmod(arg1, arg2) });
    };
}
#[no_mangle]
pub extern "C" fn xmlXPathNextSelf(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        return unsafe { (*(*ctxt).context).node };
    }
    return 0 as xmlNodePtr;
}
#[no_mangle]
pub extern "C" fn xmlXPathNextChild(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        if (unsafe { (*(*ctxt).context).node }).is_null() {
            return 0 as xmlNodePtr;
        }
        match (unsafe { (*(*(*ctxt).context).node).type_0 }) as u32 {
            1 | 3 | 4 | 5 | 6 | 7 | 8 | 12 | 14 => {
                return unsafe { (*(*(*ctxt).context).node).children };
            }
            9 | 10 | 11 | 13 => return unsafe { (*((*(*ctxt).context).node as xmlDocPtr)).children },
            15 | 16 | 17 | 2 | 18 | 19 | 20 => return 0 as xmlNodePtr,
            _ => {}
        }
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
        || (unsafe { (*cur).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        return 0 as xmlNodePtr;
    }
    return unsafe { (*cur).next };
}
extern "C" fn xmlXPathNextChildElement(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        cur = unsafe { (*(*ctxt).context).node };
        if cur.is_null() {
            return 0 as xmlNodePtr;
        }
        match (unsafe { (*cur).type_0 }) as u32 {
            1 | 11 | 5 | 6 => {
                cur = unsafe { (*cur).children };
                if !cur.is_null() {
                    if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                        return cur;
                    }
                    loop {
                        cur = unsafe { (*cur).next };
                        if !(!cur.is_null()
                            && (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32)
                        {
                            break;
                        }
                    }
                    return cur;
                }
                return 0 as xmlNodePtr;
            }
            9 | 13 => return unsafe { xmlDocGetRootElement(cur as xmlDocPtr as *const xmlDoc) },
            _ => return 0 as xmlNodePtr,
        }
    }
    match (unsafe { (*cur).type_0 }) as u32 {
        1 | 3 | 5 | 6 | 4 | 7 | 8 | 20 => {}
        _ => return 0 as xmlNodePtr,
    }
    if !(unsafe { (*cur).next }).is_null() {
        if (unsafe { (*(*cur).next).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            return unsafe { (*cur).next };
        }
        cur = unsafe { (*cur).next };
        loop {
            cur = unsafe { (*cur).next };
            if !(!cur.is_null() && (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32) {
                break;
            }
        }
        return cur;
    }
    return 0 as xmlNodePtr;
}
#[no_mangle]
pub extern "C" fn xmlXPathNextDescendant(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        if (unsafe { (*(*ctxt).context).node }).is_null() {
            return 0 as xmlNodePtr;
        }
        if (unsafe { (*(*(*ctxt).context).node).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
            || (unsafe { (*(*(*ctxt).context).node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
        {
            return 0 as xmlNodePtr;
        }
        if (unsafe { (*(*ctxt).context).node }) == (unsafe { (*(*ctxt).context).doc }) as xmlNodePtr {
            return unsafe { (*(*(*ctxt).context).doc).children };
        }
        return unsafe { (*(*(*ctxt).context).node).children };
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if !(unsafe { (*cur).children }).is_null() {
        if (unsafe { (*(*cur).children).type_0 }) as u32 != XML_ENTITY_DECL as i32 as u32 {
            cur = unsafe { (*cur).children };
            if (unsafe { (*cur).type_0 }) as u32 != XML_DTD_NODE as i32 as u32 {
                return cur;
            }
        }
    }
    if cur == (unsafe { (*(*ctxt).context).node }) {
        return 0 as xmlNodePtr;
    }
    while !(unsafe { (*cur).next }).is_null() {
        cur = unsafe { (*cur).next };
        if (unsafe { (*cur).type_0 }) as u32 != XML_ENTITY_DECL as i32 as u32
            && (unsafe { (*cur).type_0 }) as u32 != XML_DTD_NODE as i32 as u32
        {
            return cur;
        }
    }
    loop {
        cur = unsafe { (*cur).parent };
        if cur.is_null() {
            break;
        }
        if cur == (unsafe { (*(*ctxt).context).node }) {
            return 0 as xmlNodePtr;
        }
        if !(unsafe { (*cur).next }).is_null() {
            cur = unsafe { (*cur).next };
            return cur;
        }
        if cur.is_null() {
            break;
        }
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlXPathNextDescendantOrSelf(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        return unsafe { (*(*ctxt).context).node };
    }
    if (unsafe { (*(*ctxt).context).node }).is_null() {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*(*(*ctxt).context).node).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
        || (unsafe { (*(*(*ctxt).context).node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
    {
        return 0 as xmlNodePtr;
    }
    return xmlXPathNextDescendant(ctxt, cur);
}
#[no_mangle]
pub extern "C" fn xmlXPathNextParent(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        if (unsafe { (*(*ctxt).context).node }).is_null() {
            return 0 as xmlNodePtr;
        }
        match (unsafe { (*(*(*ctxt).context).node).type_0 }) as u32 {
            1 | 3 | 4 | 5 | 6 | 7 | 8 | 12 | 14 | 15 | 16 | 19 | 20 | 17 => {
                if (unsafe { (*(*(*ctxt).context).node).parent }).is_null() {
                    return (unsafe { (*(*ctxt).context).doc }) as xmlNodePtr;
                }
                if (unsafe { (*(*(*(*ctxt).context).node).parent).type_0 }) as u32
                    == XML_ELEMENT_NODE as i32 as u32
                    && ((unsafe { *((*(*(*(*ctxt).context).node).parent).name).offset(0 as i32 as isize) })
                        as i32
                        == ' ' as i32
                        || (unsafe { xmlStrEqual(
                            (*(*(*(*ctxt).context).node).parent).name,
                            b"fake node libxslt\0" as *const u8 as *const i8 as *mut xmlChar,
                        ) }) != 0)
                {
                    return 0 as xmlNodePtr;
                }
                return unsafe { (*(*(*ctxt).context).node).parent };
            }
            2 => {
                let mut att: xmlAttrPtr = (unsafe { (*(*ctxt).context).node }) as xmlAttrPtr;
                return unsafe { (*att).parent };
            }
            9 | 10 | 11 | 13 => return 0 as xmlNodePtr,
            18 => {
                let mut ns: xmlNsPtr = (unsafe { (*(*ctxt).context).node }) as xmlNsPtr;
                if !(unsafe { (*ns).next }).is_null()
                    && (unsafe { (*(*ns).next).type_0 }) as u32 != XML_NAMESPACE_DECL as i32 as u32
                {
                    return (unsafe { (*ns).next }) as xmlNodePtr;
                }
                return 0 as xmlNodePtr;
            }
            _ => {}
        }
    }
    return 0 as xmlNodePtr;
}
#[no_mangle]
pub extern "C" fn xmlXPathNextAncestor(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        if (unsafe { (*(*ctxt).context).node }).is_null() {
            return 0 as xmlNodePtr;
        }
        match (unsafe { (*(*(*ctxt).context).node).type_0 }) as u32 {
            1 | 3 | 4 | 5 | 6 | 7 | 8 | 14 | 15 | 16 | 17 | 12 | 19 | 20 => {
                if (unsafe { (*(*(*ctxt).context).node).parent }).is_null() {
                    return (unsafe { (*(*ctxt).context).doc }) as xmlNodePtr;
                }
                if (unsafe { (*(*(*(*ctxt).context).node).parent).type_0 }) as u32
                    == XML_ELEMENT_NODE as i32 as u32
                    && ((unsafe { *((*(*(*(*ctxt).context).node).parent).name).offset(0 as i32 as isize) })
                        as i32
                        == ' ' as i32
                        || (unsafe { xmlStrEqual(
                            (*(*(*(*ctxt).context).node).parent).name,
                            b"fake node libxslt\0" as *const u8 as *const i8 as *mut xmlChar,
                        ) }) != 0)
                {
                    return 0 as xmlNodePtr;
                }
                return unsafe { (*(*(*ctxt).context).node).parent };
            }
            2 => {
                let mut tmp: xmlAttrPtr = (unsafe { (*(*ctxt).context).node }) as xmlAttrPtr;
                return unsafe { (*tmp).parent };
            }
            9 | 10 | 11 | 13 => return 0 as xmlNodePtr,
            18 => {
                let mut ns: xmlNsPtr = (unsafe { (*(*ctxt).context).node }) as xmlNsPtr;
                if !(unsafe { (*ns).next }).is_null()
                    && (unsafe { (*(*ns).next).type_0 }) as u32 != XML_NAMESPACE_DECL as i32 as u32
                {
                    return (unsafe { (*ns).next }) as xmlNodePtr;
                }
                return 0 as xmlNodePtr;
            }
            _ => {}
        }
        return 0 as xmlNodePtr;
    }
    if cur == (unsafe { (*(*(*ctxt).context).doc).children }) {
        return (unsafe { (*(*ctxt).context).doc }) as xmlNodePtr;
    }
    if cur == (unsafe { (*(*ctxt).context).doc }) as xmlNodePtr {
        return 0 as xmlNodePtr;
    }
    match (unsafe { (*cur).type_0 }) as u32 {
        1 | 3 | 4 | 5 | 6 | 7 | 8 | 12 | 14 | 15 | 16 | 17 | 19 | 20 => {
            if (unsafe { (*cur).parent }).is_null() {
                return 0 as xmlNodePtr;
            }
            if (unsafe { (*(*cur).parent).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                && ((unsafe { *((*(*cur).parent).name).offset(0 as i32 as isize) }) as i32 == ' ' as i32
                    || (unsafe { xmlStrEqual(
                        (*(*cur).parent).name,
                        b"fake node libxslt\0" as *const u8 as *const i8 as *mut xmlChar,
                    ) }) != 0)
            {
                return 0 as xmlNodePtr;
            }
            return unsafe { (*cur).parent };
        }
        2 => {
            let mut att: xmlAttrPtr = cur as xmlAttrPtr;
            return unsafe { (*att).parent };
        }
        18 => {
            let mut ns_0: xmlNsPtr = cur as xmlNsPtr;
            if !(unsafe { (*ns_0).next }).is_null()
                && (unsafe { (*(*ns_0).next).type_0 }) as u32 != XML_NAMESPACE_DECL as i32 as u32
            {
                return (unsafe { (*ns_0).next }) as xmlNodePtr;
            }
            return 0 as xmlNodePtr;
        }
        9 | 10 | 11 | 13 => return 0 as xmlNodePtr,
        _ => {}
    }
    return 0 as xmlNodePtr;
}
#[no_mangle]
pub extern "C" fn xmlXPathNextAncestorOrSelf(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        return unsafe { (*(*ctxt).context).node };
    }
    return xmlXPathNextAncestor(ctxt, cur);
}
#[no_mangle]
pub extern "C" fn xmlXPathNextFollowingSibling(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*(*(*ctxt).context).node).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
        || (unsafe { (*(*(*ctxt).context).node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
    {
        return 0 as xmlNodePtr;
    }
    if cur == (unsafe { (*(*ctxt).context).doc }) as xmlNodePtr {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        return unsafe { (*(*(*ctxt).context).node).next };
    }
    return unsafe { (*cur).next };
}
#[no_mangle]
pub extern "C" fn xmlXPathNextPrecedingSibling(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*(*(*ctxt).context).node).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
        || (unsafe { (*(*(*ctxt).context).node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
    {
        return 0 as xmlNodePtr;
    }
    if cur == (unsafe { (*(*ctxt).context).doc }) as xmlNodePtr {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        return unsafe { (*(*(*ctxt).context).node).prev };
    }
    if !(unsafe { (*cur).prev }).is_null() && (unsafe { (*(*cur).prev).type_0 }) as u32 == XML_DTD_NODE as i32 as u32 {
        cur = unsafe { (*cur).prev };
        if cur.is_null() {
            return unsafe { (*(*(*ctxt).context).node).prev };
        }
    }
    return unsafe { (*cur).prev };
}
#[no_mangle]
pub extern "C" fn xmlXPathNextFollowing(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if !cur.is_null()
        && (unsafe { (*cur).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32
        && (unsafe { (*cur).type_0 }) as u32 != XML_NAMESPACE_DECL as i32 as u32
        && !(unsafe { (*cur).children }).is_null()
    {
        return unsafe { (*cur).children };
    }
    if cur.is_null() {
        cur = unsafe { (*(*ctxt).context).node };
        if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
            cur = unsafe { (*cur).parent };
        } else if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
            let mut ns: xmlNsPtr = cur as xmlNsPtr;
            if (unsafe { (*ns).next }).is_null()
                || (unsafe { (*(*ns).next).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
            {
                return 0 as xmlNodePtr;
            }
            cur = (unsafe { (*ns).next }) as xmlNodePtr;
        }
    }
    if cur.is_null() {
        return 0 as xmlNodePtr;
    }
    if !(unsafe { (*cur).next }).is_null() {
        return unsafe { (*cur).next };
    }
    loop {
        cur = unsafe { (*cur).parent };
        if cur.is_null() {
            break;
        }
        if cur == (unsafe { (*(*ctxt).context).doc }) as xmlNodePtr {
            return 0 as xmlNodePtr;
        }
        if !(unsafe { (*cur).next }).is_null() {
            return unsafe { (*cur).next };
        }
        if cur.is_null() {
            break;
        }
    }
    return cur;
}
extern "C" fn xmlXPathIsAncestor(mut ancestor: xmlNodePtr, mut node: xmlNodePtr) -> i32 {
    if ancestor.is_null() || node.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as i32;
    }
    if (unsafe { (*ancestor).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as i32;
    }
    if (unsafe { (*ancestor).doc }) != (unsafe { (*node).doc }) {
        return 0 as i32;
    }
    if ancestor == (unsafe { (*node).doc }) as xmlNodePtr {
        return 1 as i32;
    }
    if node == (unsafe { (*ancestor).doc }) as xmlNodePtr {
        return 0 as i32;
    }
    while !(unsafe { (*node).parent }).is_null() {
        if (unsafe { (*node).parent }) == ancestor {
            return 1 as i32;
        }
        node = unsafe { (*node).parent };
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlXPathNextPreceding(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        cur = unsafe { (*(*ctxt).context).node };
        if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
            cur = unsafe { (*cur).parent };
        } else if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
            let mut ns: xmlNsPtr = cur as xmlNsPtr;
            if (unsafe { (*ns).next }).is_null()
                || (unsafe { (*(*ns).next).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
            {
                return 0 as xmlNodePtr;
            }
            cur = (unsafe { (*ns).next }) as xmlNodePtr;
        }
    }
    if cur.is_null() || (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if !(unsafe { (*cur).prev }).is_null() && (unsafe { (*(*cur).prev).type_0 }) as u32 == XML_DTD_NODE as i32 as u32 {
        cur = unsafe { (*cur).prev };
    }
    loop {
        if !(unsafe { (*cur).prev }).is_null() {
            cur = unsafe { (*cur).prev };
            while !(unsafe { (*cur).last }).is_null() {
                cur = unsafe { (*cur).last };
            }
            return cur;
        }
        cur = unsafe { (*cur).parent };
        if cur.is_null() {
            return 0 as xmlNodePtr;
        }
        if cur == (unsafe { (*(*(*ctxt).context).doc).children }) {
            return 0 as xmlNodePtr;
        }
        if !(xmlXPathIsAncestor(cur, unsafe { (*(*ctxt).context).node }) != 0) {
            break;
        }
    }
    return cur;
}
extern "C" fn xmlXPathNextPrecedingInternal(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        cur = unsafe { (*(*ctxt).context).node };
        if cur.is_null() {
            return 0 as xmlNodePtr;
        }
        if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
            cur = unsafe { (*cur).parent };
        } else if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
            let mut ns: xmlNsPtr = cur as xmlNsPtr;
            if (unsafe { (*ns).next }).is_null()
                || (unsafe { (*(*ns).next).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
            {
                return 0 as xmlNodePtr;
            }
            cur = (unsafe { (*ns).next }) as xmlNodePtr;
        }
        let fresh196 = unsafe { &mut ((*ctxt).ancestor) };
        *fresh196 = unsafe { (*cur).parent };
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if !(unsafe { (*cur).prev }).is_null() && (unsafe { (*(*cur).prev).type_0 }) as u32 == XML_DTD_NODE as i32 as u32 {
        cur = unsafe { (*cur).prev };
    }
    while (unsafe { (*cur).prev }).is_null() {
        cur = unsafe { (*cur).parent };
        if cur.is_null() {
            return 0 as xmlNodePtr;
        }
        if cur == (unsafe { (*(*(*ctxt).context).doc).children }) {
            return 0 as xmlNodePtr;
        }
        if cur != (unsafe { (*ctxt).ancestor }) {
            return cur;
        }
        let fresh197 = unsafe { &mut ((*ctxt).ancestor) };
        *fresh197 = unsafe { (*cur).parent };
    }
    cur = unsafe { (*cur).prev };
    while !(unsafe { (*cur).last }).is_null() {
        cur = unsafe { (*cur).last };
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlXPathNextNamespace(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*(*(*ctxt).context).node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        if !(unsafe { (*(*ctxt).context).tmpNsList }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(
                (*(*ctxt).context).tmpNsList as *mut libc::c_void,
            ) });
        }
        let fresh198 = unsafe { &mut ((*(*ctxt).context).tmpNsList) };
        *fresh198 = unsafe { xmlGetNsList(
            (*(*ctxt).context).doc as *const xmlDoc,
            (*(*ctxt).context).node as *const xmlNode,
        ) };
        (unsafe { (*(*ctxt).context).tmpNsNr = 0 as i32 });
        if !(unsafe { (*(*ctxt).context).tmpNsList }).is_null() {
            while !(unsafe { *((*(*ctxt).context).tmpNsList).offset((*(*ctxt).context).tmpNsNr as isize) })
                .is_null()
            {
                let fresh199 = unsafe { &mut ((*(*ctxt).context).tmpNsNr) };
                *fresh199 += 1;
            }
        }
        return (unsafe { xmlXPathXMLNamespace }) as xmlNodePtr;
    }
    if (unsafe { (*(*ctxt).context).tmpNsNr }) > 0 as i32 {
        let fresh200 = unsafe { &mut ((*(*ctxt).context).tmpNsNr) };
        *fresh200 -= 1;
        return (unsafe { *((*(*ctxt).context).tmpNsList).offset(*fresh200 as isize) }) as xmlNodePtr;
    } else {
        if !(unsafe { (*(*ctxt).context).tmpNsList }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(
                (*(*ctxt).context).tmpNsList as *mut libc::c_void,
            ) });
        }
        let fresh201 = unsafe { &mut ((*(*ctxt).context).tmpNsList) };
        *fresh201 = 0 as *mut xmlNsPtr;
        return 0 as xmlNodePtr;
    };
}
#[no_mangle]
pub extern "C" fn xmlXPathNextAttribute(
    mut ctxt: xmlXPathParserContextPtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*(*ctxt).context).node }).is_null() {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*(*(*ctxt).context).node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        if (unsafe { (*(*ctxt).context).node }) == (unsafe { (*(*ctxt).context).doc }) as xmlNodePtr {
            return 0 as xmlNodePtr;
        }
        return (unsafe { (*(*(*ctxt).context).node).properties }) as xmlNodePtr;
    }
    return (unsafe { (*cur).next }) as xmlNodePtr;
}
#[no_mangle]
pub extern "C" fn xmlXPathRoot(mut ctxt: xmlXPathParserContextPtr) {
    if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
        return;
    }
    valuePush(
        ctxt,
        xmlXPathCacheNewNodeSet(unsafe { (*ctxt).context }, (unsafe { (*(*ctxt).context).doc }) as xmlNodePtr),
    );
}
#[no_mangle]
pub extern "C" fn xmlXPathLastFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    if ctxt.is_null() {
        return;
    }
    if nargs != 0 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 0 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if (unsafe { (*(*ctxt).context).contextSize }) >= 0 as i32 {
        valuePush(
            ctxt,
            xmlXPathCacheNewFloat(unsafe { (*ctxt).context }, (unsafe { (*(*ctxt).context).contextSize }) as f64),
        );
    } else {
        xmlXPathErr(ctxt, XPATH_INVALID_CTXT_SIZE as i32);
        return;
    };
}
#[no_mangle]
pub extern "C" fn xmlXPathPositionFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    if ctxt.is_null() {
        return;
    }
    if nargs != 0 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 0 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if (unsafe { (*(*ctxt).context).proximityPosition }) >= 0 as i32 {
        valuePush(
            ctxt,
            xmlXPathCacheNewFloat(unsafe { (*ctxt).context }, (unsafe { (*(*ctxt).context).proximityPosition }) as f64),
        );
    } else {
        xmlXPathErr(ctxt, XPATH_INVALID_CTXT_POSITION as i32);
        return;
    };
}
#[no_mangle]
pub extern "C" fn xmlXPathCountFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut cur: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if (unsafe { (*ctxt).value }).is_null()
        || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    cur = valuePop(ctxt);
    if cur.is_null() || (unsafe { (*cur).nodesetval }).is_null() {
        valuePush(
            ctxt,
            xmlXPathCacheNewFloat(unsafe { (*ctxt).context }, 0 as i32 as f64),
        );
    } else {
        valuePush(
            ctxt,
            xmlXPathCacheNewFloat(unsafe { (*ctxt).context }, (unsafe { (*(*cur).nodesetval).nodeNr }) as f64),
        );
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, cur);
}
extern "C" fn xmlXPathGetElementsByIds(
    mut doc: xmlDocPtr,
    mut ids: *const xmlChar,
) -> xmlNodeSetPtr {
    let mut ret: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut cur: *const xmlChar = ids;
    let mut ID: *mut xmlChar = 0 as *mut xmlChar;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut elem: xmlNodePtr = 0 as xmlNodePtr;
    if ids.is_null() {
        return 0 as xmlNodeSetPtr;
    }
    ret = xmlXPathNodeSetCreate(0 as xmlNodePtr);
    if ret.is_null() {
        return ret;
    }
    while (unsafe { *cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
        || (unsafe { *cur }) as i32 == 0xd as i32
    {
        cur = unsafe { cur.offset(1) };
    }
    while (unsafe { *cur }) as i32 != 0 as i32 {
        while !((unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32)
            && (unsafe { *cur }) as i32 != 0 as i32
        {
            cur = unsafe { cur.offset(1) };
        }
        ID = unsafe { xmlStrndup(ids, cur.offset_from(ids) as i64 as i32) };
        if !ID.is_null() {
            attr = unsafe { xmlGetID(doc, ID) };
            if !attr.is_null() {
                if (unsafe { (*attr).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
                    elem = unsafe { (*attr).parent };
                } else if (unsafe { (*attr).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                    elem = attr as xmlNodePtr;
                } else {
                    elem = 0 as xmlNodePtr;
                }
                if !elem.is_null() {
                    xmlXPathNodeSetAdd(ret, elem);
                }
            }
            (unsafe { xmlFree.expect("non-null function pointer")(ID as *mut libc::c_void) });
        }
        while (unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32
        {
            cur = unsafe { cur.offset(1) };
        }
        ids = cur;
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathIdFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut tokens: *mut xmlChar = 0 as *mut xmlChar;
    let mut ret: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut obj: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    obj = valuePop(ctxt);
    if obj.is_null() {
        xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
        return;
    }
    if (unsafe { (*obj).type_0 }) as u32 == XPATH_NODESET as i32 as u32
        || (unsafe { (*obj).type_0 }) as u32 == XPATH_XSLT_TREE as i32 as u32
    {
        let mut ns: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
        let mut i: i32 = 0;
        ret = xmlXPathNodeSetCreate(0 as xmlNodePtr);
        if !(unsafe { (*obj).nodesetval }).is_null() {
            i = 0 as i32;
            while i < (unsafe { (*(*obj).nodesetval).nodeNr }) {
                tokens =
                    xmlXPathCastNodeToString(unsafe { *((*(*obj).nodesetval).nodeTab).offset(i as isize) });
                ns = xmlXPathGetElementsByIds(unsafe { (*(*ctxt).context).doc }, tokens);
                ret = xmlXPathNodeSetMerge(ret, ns);
                xmlXPathFreeNodeSet(ns);
                if !tokens.is_null() {
                    (unsafe { xmlFree.expect("non-null function pointer")(tokens as *mut libc::c_void) });
                }
                i += 1;
            }
        }
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, obj);
        valuePush(ctxt, xmlXPathCacheWrapNodeSet(unsafe { (*ctxt).context }, ret));
        return;
    }
    obj = xmlXPathCacheConvertString(unsafe { (*ctxt).context }, obj);
    if obj.is_null() {
        return;
    }
    ret = xmlXPathGetElementsByIds(unsafe { (*(*ctxt).context).doc }, unsafe { (*obj).stringval });
    valuePush(ctxt, xmlXPathCacheWrapNodeSet(unsafe { (*ctxt).context }, ret));
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, obj);
}
#[no_mangle]
pub extern "C" fn xmlXPathLocalNameFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut cur: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if ctxt.is_null() {
        return;
    }
    if nargs == 0 as i32 {
        valuePush(
            ctxt,
            xmlXPathCacheNewNodeSet(unsafe { (*ctxt).context }, unsafe { (*(*ctxt).context).node }),
        );
        nargs = 1 as i32;
    }
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if (unsafe { (*ctxt).value }).is_null()
        || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    cur = valuePop(ctxt);
    if (unsafe { (*cur).nodesetval }).is_null() || (unsafe { (*(*cur).nodesetval).nodeNr }) == 0 as i32 {
        valuePush(
            ctxt,
            xmlXPathCacheNewCString(unsafe { (*ctxt).context }, b"\0" as *const u8 as *const i8),
        );
    } else {
        let mut i: i32 = 0 as i32;
        match (unsafe { (**((*(*cur).nodesetval).nodeTab).offset(i as isize)).type_0 }) as u32 {
            1 | 2 | 7 => {
                if (unsafe { *((**((*(*cur).nodesetval).nodeTab).offset(i as isize)).name)
                    .offset(0 as i32 as isize) }) as i32
                    == ' ' as i32
                {
                    valuePush(
                        ctxt,
                        xmlXPathCacheNewCString(unsafe { (*ctxt).context }, b"\0" as *const u8 as *const i8),
                    );
                } else {
                    valuePush(
                        ctxt,
                        xmlXPathCacheNewString(
                            unsafe { (*ctxt).context },
                            unsafe { (**((*(*cur).nodesetval).nodeTab).offset(i as isize)).name },
                        ),
                    );
                }
            }
            18 => {
                valuePush(
                    ctxt,
                    xmlXPathCacheNewString(
                        unsafe { (*ctxt).context },
                        unsafe { (*(*((*(*cur).nodesetval).nodeTab).offset(i as isize) as xmlNsPtr)).prefix },
                    ),
                );
            }
            _ => {
                valuePush(
                    ctxt,
                    xmlXPathCacheNewCString(unsafe { (*ctxt).context }, b"\0" as *const u8 as *const i8),
                );
            }
        }
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, cur);
}
#[no_mangle]
pub extern "C" fn xmlXPathNamespaceURIFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut cur: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if ctxt.is_null() {
        return;
    }
    if nargs == 0 as i32 {
        valuePush(
            ctxt,
            xmlXPathCacheNewNodeSet(unsafe { (*ctxt).context }, unsafe { (*(*ctxt).context).node }),
        );
        nargs = 1 as i32;
    }
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if (unsafe { (*ctxt).value }).is_null()
        || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    cur = valuePop(ctxt);
    if (unsafe { (*cur).nodesetval }).is_null() || (unsafe { (*(*cur).nodesetval).nodeNr }) == 0 as i32 {
        valuePush(
            ctxt,
            xmlXPathCacheNewCString(unsafe { (*ctxt).context }, b"\0" as *const u8 as *const i8),
        );
    } else {
        let mut i: i32 = 0 as i32;
        match (unsafe { (**((*(*cur).nodesetval).nodeTab).offset(i as isize)).type_0 }) as u32 {
            1 | 2 => {
                if (unsafe { (**((*(*cur).nodesetval).nodeTab).offset(i as isize)).ns }).is_null() {
                    valuePush(
                        ctxt,
                        xmlXPathCacheNewCString(unsafe { (*ctxt).context }, b"\0" as *const u8 as *const i8),
                    );
                } else {
                    valuePush(
                        ctxt,
                        xmlXPathCacheNewString(
                            unsafe { (*ctxt).context },
                            unsafe { (*(**((*(*cur).nodesetval).nodeTab).offset(i as isize)).ns).href },
                        ),
                    );
                }
            }
            _ => {
                valuePush(
                    ctxt,
                    xmlXPathCacheNewCString(unsafe { (*ctxt).context }, b"\0" as *const u8 as *const i8),
                );
            }
        }
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, cur);
}
extern "C" fn xmlXPathNameFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut cur: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if nargs == 0 as i32 {
        valuePush(
            ctxt,
            xmlXPathCacheNewNodeSet(unsafe { (*ctxt).context }, unsafe { (*(*ctxt).context).node }),
        );
        nargs = 1 as i32;
    }
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if (unsafe { (*ctxt).value }).is_null()
        || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    cur = valuePop(ctxt);
    if (unsafe { (*cur).nodesetval }).is_null() || (unsafe { (*(*cur).nodesetval).nodeNr }) == 0 as i32 {
        valuePush(
            ctxt,
            xmlXPathCacheNewCString(unsafe { (*ctxt).context }, b"\0" as *const u8 as *const i8),
        );
    } else {
        let mut i: i32 = 0 as i32;
        match (unsafe { (**((*(*cur).nodesetval).nodeTab).offset(i as isize)).type_0 }) as u32 {
            1 | 2 => {
                if (unsafe { *((**((*(*cur).nodesetval).nodeTab).offset(i as isize)).name)
                    .offset(0 as i32 as isize) }) as i32
                    == ' ' as i32
                {
                    valuePush(
                        ctxt,
                        xmlXPathCacheNewCString(unsafe { (*ctxt).context }, b"\0" as *const u8 as *const i8),
                    );
                } else if (unsafe { (**((*(*cur).nodesetval).nodeTab).offset(i as isize)).ns }).is_null()
                    || (unsafe { (*(**((*(*cur).nodesetval).nodeTab).offset(i as isize)).ns).prefix })
                        .is_null()
                {
                    valuePush(
                        ctxt,
                        xmlXPathCacheNewString(
                            unsafe { (*ctxt).context },
                            unsafe { (**((*(*cur).nodesetval).nodeTab).offset(i as isize)).name },
                        ),
                    );
                } else {
                    let mut fullname: *mut xmlChar = 0 as *mut xmlChar;
                    fullname = unsafe { xmlBuildQName(
                        (**((*(*cur).nodesetval).nodeTab).offset(i as isize)).name,
                        (*(**((*(*cur).nodesetval).nodeTab).offset(i as isize)).ns).prefix,
                        0 as *mut xmlChar,
                        0 as i32,
                    ) };
                    if fullname
                        == (unsafe { (**((*(*cur).nodesetval).nodeTab).offset(i as isize)).name })
                            as *mut xmlChar
                    {
                        fullname =
                            unsafe { xmlStrdup((**((*(*cur).nodesetval).nodeTab).offset(i as isize)).name) };
                    }
                    if fullname.is_null() {
                        xmlXPathErr(ctxt, XPATH_MEMORY_ERROR as i32);
                        return;
                    }
                    valuePush(ctxt, xmlXPathCacheWrapString(unsafe { (*ctxt).context }, fullname));
                }
            }
            _ => {
                valuePush(
                    ctxt,
                    xmlXPathCacheNewNodeSet(
                        unsafe { (*ctxt).context },
                        unsafe { *((*(*cur).nodesetval).nodeTab).offset(i as isize) },
                    ),
                );
                xmlXPathLocalNameFunction(ctxt, 1 as i32);
            }
        }
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, cur);
}
#[no_mangle]
pub extern "C" fn xmlXPathStringFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut cur: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if ctxt.is_null() {
        return;
    }
    if nargs == 0 as i32 {
        valuePush(
            ctxt,
            xmlXPathCacheWrapString(
                unsafe { (*ctxt).context },
                xmlXPathCastNodeToString(unsafe { (*(*ctxt).context).node }),
            ),
        );
        return;
    }
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    cur = valuePop(ctxt);
    if cur.is_null() {
        xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
        return;
    }
    valuePush(ctxt, xmlXPathCacheConvertString(unsafe { (*ctxt).context }, cur));
}
#[no_mangle]
pub extern "C" fn xmlXPathStringLengthFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut cur: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if nargs == 0 as i32 {
        if ctxt.is_null() || (unsafe { (*ctxt).context }).is_null() {
            return;
        }
        if (unsafe { (*(*ctxt).context).node }).is_null() {
            valuePush(
                ctxt,
                xmlXPathCacheNewFloat(unsafe { (*ctxt).context }, 0 as i32 as f64),
            );
        } else {
            let mut content: *mut xmlChar = 0 as *mut xmlChar;
            content = xmlXPathCastNodeToString(unsafe { (*(*ctxt).context).node });
            valuePush(
                ctxt,
                xmlXPathCacheNewFloat(unsafe { (*ctxt).context }, (unsafe { xmlUTF8Strlen(content) }) as f64),
            );
            (unsafe { xmlFree.expect("non-null function pointer")(content as *mut libc::c_void) });
        }
        return;
    }
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    cur = valuePop(ctxt);
    valuePush(
        ctxt,
        xmlXPathCacheNewFloat(unsafe { (*ctxt).context }, (unsafe { xmlUTF8Strlen((*cur).stringval) }) as f64),
    );
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, cur);
}
#[no_mangle]
pub extern "C" fn xmlXPathConcatFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut cur: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut newobj: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
    if ctxt.is_null() {
        return;
    }
    if nargs < 2 as i32 {
        if ctxt.is_null() {
            return;
        }
        if nargs != 2 as i32 {
            xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
            return;
        }
        if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 2 as i32 {
            xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
            return;
        }
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    cur = valuePop(ctxt);
    if cur.is_null() || (unsafe { (*cur).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, cur);
        return;
    }
    nargs -= 1;
    while nargs > 0 as i32 {
        if !(unsafe { (*ctxt).value }).is_null()
            && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32
        {
            xmlXPathStringFunction(ctxt, 1 as i32);
        }
        newobj = valuePop(ctxt);
        if newobj.is_null() || (unsafe { (*newobj).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
            xmlXPathReleaseObject(unsafe { (*ctxt).context }, newobj);
            xmlXPathReleaseObject(unsafe { (*ctxt).context }, cur);
            xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
            return;
        }
        tmp = unsafe { xmlStrcat((*newobj).stringval, (*cur).stringval) };
        let fresh202 = unsafe { &mut ((*newobj).stringval) };
        *fresh202 = unsafe { (*cur).stringval };
        let fresh203 = unsafe { &mut ((*cur).stringval) };
        *fresh203 = tmp;
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, newobj);
        nargs -= 1;
    }
    valuePush(ctxt, cur);
}
#[no_mangle]
pub extern "C" fn xmlXPathContainsFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut hay: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut needle: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if ctxt.is_null() {
        return;
    }
    if nargs != 2 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 2 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    needle = valuePop(ctxt);
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    hay = valuePop(ctxt);
    if hay.is_null() || (unsafe { (*hay).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, hay);
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, needle);
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    if !(unsafe { xmlStrstr((*hay).stringval, (*needle).stringval) }).is_null() {
        valuePush(ctxt, xmlXPathCacheNewBoolean(unsafe { (*ctxt).context }, 1 as i32));
    } else {
        valuePush(ctxt, xmlXPathCacheNewBoolean(unsafe { (*ctxt).context }, 0 as i32));
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, hay);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, needle);
}
#[no_mangle]
pub extern "C" fn xmlXPathStartsWithFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut hay: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut needle: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut n: i32 = 0;
    if ctxt.is_null() {
        return;
    }
    if nargs != 2 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 2 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    needle = valuePop(ctxt);
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    hay = valuePop(ctxt);
    if hay.is_null() || (unsafe { (*hay).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, hay);
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, needle);
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    n = unsafe { xmlStrlen((*needle).stringval) };
    if (unsafe { xmlStrncmp((*hay).stringval, (*needle).stringval, n) }) != 0 {
        valuePush(ctxt, xmlXPathCacheNewBoolean(unsafe { (*ctxt).context }, 0 as i32));
    } else {
        valuePush(ctxt, xmlXPathCacheNewBoolean(unsafe { (*ctxt).context }, 1 as i32));
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, hay);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, needle);
}
#[no_mangle]
pub extern "C" fn xmlXPathSubstringFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut str: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut start: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut len: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut le: f64 = 0 as i32 as f64;
    let mut in_0: f64 = 0.;
    let mut i: i32 = 1 as i32;
    let mut j: i32 = 2147483647 as i32;
    if nargs < 2 as i32 {
        if ctxt.is_null() {
            return;
        }
        if nargs != 2 as i32 {
            xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
            return;
        }
        if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 2 as i32 {
            xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
            return;
        }
    }
    if nargs > 3 as i32 {
        if ctxt.is_null() {
            return;
        }
        if nargs != 3 as i32 {
            xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
            return;
        }
        if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 3 as i32 {
            xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
            return;
        }
    }
    if nargs == 3 as i32 {
        if !(unsafe { (*ctxt).value }).is_null()
            && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32
        {
            xmlXPathNumberFunction(ctxt, 1 as i32);
        }
        if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32
        {
            xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
            return;
        }
        len = valuePop(ctxt);
        le = unsafe { (*len).floatval };
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, len);
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathNumberFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    start = valuePop(ctxt);
    in_0 = unsafe { (*start).floatval };
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, start);
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    str = valuePop(ctxt);
    if !(in_0 < 2147483647 as i32 as f64) {
        i = 2147483647 as i32;
    } else if in_0 >= 1.0f64 {
        i = in_0 as i32;
        if in_0 - (unsafe { floor(in_0) }) >= 0.5f64 {
            i += 1 as i32;
        }
    }
    if nargs == 3 as i32 {
        let mut rin: f64 = 0.;
        let mut rle: f64 = 0.;
        let mut end: f64 = 0.;
        rin = unsafe { floor(in_0) };
        if in_0 - rin >= 0.5f64 {
            rin += 1.0f64;
        }
        rle = unsafe { floor(le) };
        if le - rle >= 0.5f64 {
            rle += 1.0f64;
        }
        end = rin + rle;
        if !(end >= 1.0f64) {
            j = 1 as i32;
        } else if end < 2147483647 as i32 as f64 {
            j = end as i32;
        }
    }
    if i < j {
        let mut ret: *mut xmlChar = unsafe { xmlUTF8Strsub((*str).stringval, i - 1 as i32, j - i) };
        valuePush(ctxt, xmlXPathCacheNewString(unsafe { (*ctxt).context }, ret));
        (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
    } else {
        valuePush(
            ctxt,
            xmlXPathCacheNewCString(unsafe { (*ctxt).context }, b"\0" as *const u8 as *const i8),
        );
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, str);
}
#[no_mangle]
pub extern "C" fn xmlXPathSubstringBeforeFunction(
    mut ctxt: xmlXPathParserContextPtr,
    mut nargs: i32,
) {
    let mut str: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut find: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut target: xmlBufPtr = 0 as *mut xmlBuf;
    let mut point: *const xmlChar = 0 as *const xmlChar;
    let mut offset: i32 = 0;
    if ctxt.is_null() {
        return;
    }
    if nargs != 2 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 2 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    find = valuePop(ctxt);
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    str = valuePop(ctxt);
    target = unsafe { xmlBufCreate() };
    if !target.is_null() {
        point = unsafe { xmlStrstr((*str).stringval, (*find).stringval) };
        if !point.is_null() {
            offset = (unsafe { point.offset_from((*str).stringval) }) as i64 as i32;
            (unsafe { xmlBufAdd(target, (*str).stringval, offset) });
        }
        valuePush(
            ctxt,
            xmlXPathCacheNewString(unsafe { (*ctxt).context }, unsafe { xmlBufContent(target as *const xmlBuf) }),
        );
        (unsafe { xmlBufFree(target) });
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, str);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, find);
}
#[no_mangle]
pub extern "C" fn xmlXPathSubstringAfterFunction(
    mut ctxt: xmlXPathParserContextPtr,
    mut nargs: i32,
) {
    let mut str: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut find: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut target: xmlBufPtr = 0 as *mut xmlBuf;
    let mut point: *const xmlChar = 0 as *const xmlChar;
    let mut offset: i32 = 0;
    if ctxt.is_null() {
        return;
    }
    if nargs != 2 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 2 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    find = valuePop(ctxt);
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    str = valuePop(ctxt);
    target = unsafe { xmlBufCreate() };
    if !target.is_null() {
        point = unsafe { xmlStrstr((*str).stringval, (*find).stringval) };
        if !point.is_null() {
            offset =
                (unsafe { point.offset_from((*str).stringval) }) as i64 as i32 + (unsafe { xmlStrlen((*find).stringval) });
            (unsafe { xmlBufAdd(
                target,
                &mut *((*str).stringval).offset(offset as isize),
                xmlStrlen((*str).stringval) - offset,
            ) });
        }
        valuePush(
            ctxt,
            xmlXPathCacheNewString(unsafe { (*ctxt).context }, unsafe { xmlBufContent(target as *const xmlBuf) }),
        );
        (unsafe { xmlBufFree(target) });
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, str);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, find);
}
#[no_mangle]
pub extern "C" fn xmlXPathNormalizeFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut source: *mut xmlChar = 0 as *mut xmlChar;
    let mut target: *mut xmlChar = 0 as *mut xmlChar;
    let mut blank: i32 = 0;
    if ctxt.is_null() {
        return;
    }
    if nargs == 0 as i32 {
        valuePush(
            ctxt,
            xmlXPathCacheWrapString(
                unsafe { (*ctxt).context },
                xmlXPathCastNodeToString(unsafe { (*(*ctxt).context).node }),
            ),
        );
        nargs = 1 as i32;
    }
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    source = unsafe { (*(*ctxt).value).stringval };
    if source.is_null() {
        return;
    }
    target = source;
    while (unsafe { *source }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *source }) as i32 && (unsafe { *source }) as i32 <= 0xa as i32
        || (unsafe { *source }) as i32 == 0xd as i32
    {
        source = unsafe { source.offset(1) };
    }
    blank = 0 as i32;
    while (unsafe { *source }) != 0 {
        if (unsafe { *source }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *source }) as i32 && (unsafe { *source }) as i32 <= 0xa as i32
            || (unsafe { *source }) as i32 == 0xd as i32
        {
            blank = 1 as i32;
        } else {
            if blank != 0 {
                let fresh204 = target;
                target = unsafe { target.offset(1) };
                (unsafe { *fresh204 = 0x20 as i32 as xmlChar });
                blank = 0 as i32;
            }
            let fresh205 = target;
            target = unsafe { target.offset(1) };
            (unsafe { *fresh205 = *source });
        }
        source = unsafe { source.offset(1) };
    }
    (unsafe { *target = 0 as i32 as xmlChar });
}
#[no_mangle]
pub extern "C" fn xmlXPathTranslateFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut str: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut from: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut to: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut target: xmlBufPtr = 0 as *mut xmlBuf;
    let mut offset: i32 = 0;
    let mut max: i32 = 0;
    let mut ch: xmlChar = 0;
    let mut point: *const xmlChar = 0 as *const xmlChar;
    let mut cptr: *mut xmlChar = 0 as *mut xmlChar;
    if ctxt.is_null() {
        return;
    }
    if nargs != 3 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 3 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    to = valuePop(ctxt);
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    from = valuePop(ctxt);
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    str = valuePop(ctxt);
    target = unsafe { xmlBufCreate() };
    if !target.is_null() {
        max = unsafe { xmlUTF8Strlen((*to).stringval) };
        cptr = unsafe { (*str).stringval };
        loop {
            ch = unsafe { *cptr };
            if !(ch != 0) {
                break;
            }
            offset = unsafe { xmlUTF8Strloc((*from).stringval, cptr) };
            if offset >= 0 as i32 {
                if offset < max {
                    point = unsafe { xmlUTF8Strpos((*to).stringval, offset) };
                    if !point.is_null() {
                        (unsafe { xmlBufAdd(target, point, xmlUTF8Strsize(point, 1 as i32)) });
                    }
                }
            } else {
                (unsafe { xmlBufAdd(target, cptr, xmlUTF8Strsize(cptr, 1 as i32)) });
            }
            cptr = unsafe { cptr.offset(1) };
            if !(ch as i32 & 0x80 as i32 != 0) {
                continue;
            }
            if ch as i32 & 0xc0 as i32 != 0xc0 as i32 {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"xmlXPathTranslateFunction: Invalid UTF8 string\n\0" as *const u8 as *const i8,
                ) });
                break;
            } else {
                loop {
                    ch = ((ch as i32) << 1 as i32) as xmlChar;
                    if !(ch as i32 & 0x80 as i32 != 0) {
                        break;
                    }
                    let fresh206 = cptr;
                    cptr = unsafe { cptr.offset(1) };
                    if !((unsafe { *fresh206 }) as i32 & 0xc0 as i32 != 0x80 as i32) {
                        continue;
                    }
                    (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"xmlXPathTranslateFunction: Invalid UTF8 string\n\0" as *const u8
                            as *const i8,
                    ) });
                    break;
                }
                if ch as i32 & 0x80 as i32 != 0 {
                    break;
                }
            }
        }
    }
    valuePush(
        ctxt,
        xmlXPathCacheNewString(unsafe { (*ctxt).context }, unsafe { xmlBufContent(target as *const xmlBuf) }),
    );
    (unsafe { xmlBufFree(target) });
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, str);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, from);
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, to);
}
#[no_mangle]
pub extern "C" fn xmlXPathBooleanFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut cur: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    cur = valuePop(ctxt);
    if cur.is_null() {
        xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
        return;
    }
    cur = xmlXPathCacheConvertBoolean(unsafe { (*ctxt).context }, cur);
    valuePush(ctxt, cur);
}
#[no_mangle]
pub extern "C" fn xmlXPathNotFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_BOOLEAN as i32 as u32 {
        xmlXPathBooleanFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_BOOLEAN as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    (unsafe { (*(*ctxt).value).boolval = ((*(*ctxt).value).boolval == 0) as i32 });
}
#[no_mangle]
pub extern "C" fn xmlXPathTrueFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    if ctxt.is_null() {
        return;
    }
    if nargs != 0 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 0 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    valuePush(ctxt, xmlXPathCacheNewBoolean(unsafe { (*ctxt).context }, 1 as i32));
}
#[no_mangle]
pub extern "C" fn xmlXPathFalseFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    if ctxt.is_null() {
        return;
    }
    if nargs != 0 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 0 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    valuePush(ctxt, xmlXPathCacheNewBoolean(unsafe { (*ctxt).context }, 0 as i32));
}
#[no_mangle]
pub extern "C" fn xmlXPathLangFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut current_block: u64;
    let mut val: xmlXPathObjectPtr = 0 as xmlXPathObjectPtr;
    let mut theLang: *const xmlChar = 0 as *const xmlChar;
    let mut lang: *const xmlChar = 0 as *const xmlChar;
    let mut ret: i32 = 0 as i32;
    let mut i: i32 = 0;
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    val = valuePop(ctxt);
    lang = unsafe { (*val).stringval };
    theLang = unsafe { xmlNodeGetLang((*(*ctxt).context).node as *const xmlNode) };
    if !theLang.is_null() && !lang.is_null() {
        i = 0 as i32;
        loop {
            if !((unsafe { *lang.offset(i as isize) }) as i32 != 0 as i32) {
                current_block = 2232869372362427478;
                break;
            }
            if ({
                let mut __res: i32 = 0;
                if ::std::mem::size_of::<xmlChar>() as u64 > 1 as i32 as u64 {
                    if 0 != 0 {
                        let mut __c: i32 = (unsafe { *lang.offset(i as isize) }) as i32;
                        __res = if __c < -(128 as i32) || __c > 255 as i32 {
                            __c
                        } else {
                            unsafe { *(*__ctype_toupper_loc()).offset(__c as isize) }
                        };
                    } else {
                        __res = toupper((unsafe { *lang.offset(i as isize) }) as i32);
                    }
                } else {
                    __res =
                        unsafe { *(*__ctype_toupper_loc()).offset(*lang.offset(i as isize) as i32 as isize) };
                }
                __res
            }) != ({
                let mut __res: i32 = 0;
                if ::std::mem::size_of::<xmlChar>() as u64 > 1 as i32 as u64 {
                    if 0 != 0 {
                        let mut __c: i32 = (unsafe { *theLang.offset(i as isize) }) as i32;
                        __res = if __c < -(128 as i32) || __c > 255 as i32 {
                            __c
                        } else {
                            unsafe { *(*__ctype_toupper_loc()).offset(__c as isize) }
                        };
                    } else {
                        __res = toupper((unsafe { *theLang.offset(i as isize) }) as i32);
                    }
                } else {
                    __res = unsafe { *(*__ctype_toupper_loc())
                        .offset(*theLang.offset(i as isize) as i32 as isize) };
                }
                __res
            }) {
                current_block = 4678190163169490533;
                break;
            }
            i += 1;
        }
        match current_block {
            4678190163169490533 => {}
            _ => {
                if (unsafe { *theLang.offset(i as isize) }) as i32 == 0 as i32
                    || (unsafe { *theLang.offset(i as isize) }) as i32 == '-' as i32
                {
                    ret = 1 as i32;
                }
            }
        }
    }
    if !theLang.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(theLang as *mut libc::c_void) });
    }
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, val);
    valuePush(ctxt, xmlXPathCacheNewBoolean(unsafe { (*ctxt).context }, ret));
}
#[no_mangle]
pub extern "C" fn xmlXPathNumberFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut cur: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut res: f64 = 0.;
    if ctxt.is_null() {
        return;
    }
    if nargs == 0 as i32 {
        if (unsafe { (*(*ctxt).context).node }).is_null() {
            valuePush(ctxt, xmlXPathCacheNewFloat(unsafe { (*ctxt).context }, 0.0f64));
        } else {
            let mut content: *mut xmlChar =
                unsafe { xmlNodeGetContent((*(*ctxt).context).node as *const xmlNode) };
            res = xmlXPathStringEvalNumber(content);
            valuePush(ctxt, xmlXPathCacheNewFloat(unsafe { (*ctxt).context }, res));
            (unsafe { xmlFree.expect("non-null function pointer")(content as *mut libc::c_void) });
        }
        return;
    }
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    cur = valuePop(ctxt);
    valuePush(ctxt, xmlXPathCacheConvertNumber(unsafe { (*ctxt).context }, cur));
}
#[no_mangle]
pub extern "C" fn xmlXPathSumFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut cur: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut i: i32 = 0;
    let mut res: f64 = 0.0f64;
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if (unsafe { (*ctxt).value }).is_null()
        || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_XSLT_TREE as i32 as u32
    {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    cur = valuePop(ctxt);
    if !(unsafe { (*cur).nodesetval }).is_null() && (unsafe { (*(*cur).nodesetval).nodeNr }) != 0 as i32 {
        i = 0 as i32;
        while i < (unsafe { (*(*cur).nodesetval).nodeNr }) {
            res += xmlXPathCastNodeToNumber(unsafe { *((*(*cur).nodesetval).nodeTab).offset(i as isize) });
            i += 1;
        }
    }
    valuePush(ctxt, xmlXPathCacheNewFloat(unsafe { (*ctxt).context }, res));
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, cur);
}
#[no_mangle]
pub extern "C" fn xmlXPathFloorFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathNumberFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    (unsafe { (*(*ctxt).value).floatval = floor((*(*ctxt).value).floatval) });
}
#[no_mangle]
pub extern "C" fn xmlXPathCeilingFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathNumberFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    (unsafe { (*(*ctxt).value).floatval = ceil((*(*ctxt).value).floatval) });
}
#[no_mangle]
pub extern "C" fn xmlXPathRoundFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut f: f64 = 0.;
    if ctxt.is_null() {
        return;
    }
    if nargs != 1 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 1 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathNumberFunction(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return;
    }
    f = unsafe { (*(*ctxt).value).floatval };
    if f >= -0.5f64 && f < 0.5f64 {
        (unsafe { (*(*ctxt).value).floatval *= 0.0f64 });
    } else {
        let mut rounded: f64 = unsafe { floor(f) };
        if f - rounded >= 0.5f64 {
            rounded += 1.0f64;
        }
        (unsafe { (*(*ctxt).value).floatval = rounded });
    };
}
extern "C" fn xmlXPathCurrentChar(mut ctxt: xmlXPathParserContextPtr, mut len: *mut i32) -> i32 {
    let mut current_block: u64;
    let mut c: u8 = 0;
    let mut val: u32 = 0;
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    if ctxt.is_null() {
        return 0 as i32;
    }
    cur = unsafe { (*ctxt).cur };
    c = unsafe { *cur };
    if c as i32 & 0x80 as i32 != 0 {
        if !((unsafe { *cur.offset(1 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32) {
            if c as i32 & 0xe0 as i32 == 0xe0 as i32 {
                if (unsafe { *cur.offset(2 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                    current_block = 11250042212206947267;
                } else if c as i32 & 0xf0 as i32 == 0xf0 as i32 {
                    if c as i32 & 0xf8 as i32 != 0xf0 as i32
                        || (unsafe { *cur.offset(3 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32
                    {
                        current_block = 11250042212206947267;
                    } else {
                        (unsafe { *len = 4 as i32 });
                        val = (((unsafe { *cur.offset(0 as i32 as isize) }) as i32 & 0x7 as i32) << 18 as i32)
                            as u32;
                        val |= (((unsafe { *cur.offset(1 as i32 as isize) }) as i32 & 0x3f as i32) << 12 as i32)
                            as u32;
                        val |= (((unsafe { *cur.offset(2 as i32 as isize) }) as i32 & 0x3f as i32) << 6 as i32)
                            as u32;
                        val |= ((unsafe { *cur.offset(3 as i32 as isize) }) as i32 & 0x3f as i32) as u32;
                        current_block = 10043043949733653460;
                    }
                } else {
                    (unsafe { *len = 3 as i32 });
                    val =
                        (((unsafe { *cur.offset(0 as i32 as isize) }) as i32 & 0xf as i32) << 12 as i32) as u32;
                    val |=
                        (((unsafe { *cur.offset(1 as i32 as isize) }) as i32 & 0x3f as i32) << 6 as i32) as u32;
                    val |= ((unsafe { *cur.offset(2 as i32 as isize) }) as i32 & 0x3f as i32) as u32;
                    current_block = 10043043949733653460;
                }
            } else {
                (unsafe { *len = 2 as i32 });
                val = (((unsafe { *cur.offset(0 as i32 as isize) }) as i32 & 0x1f as i32) << 6 as i32) as u32;
                val |= ((unsafe { *cur.offset(1 as i32 as isize) }) as i32 & 0x3f as i32) as u32;
                current_block = 10043043949733653460;
            }
            match current_block {
                11250042212206947267 => {}
                _ => {
                    if if val < 0x100 as i32 as u32 {
                        (0x9 as i32 as u32 <= val && val <= 0xa as i32 as u32
                            || val == 0xd as i32 as u32
                            || 0x20 as i32 as u32 <= val) as i32
                    } else {
                        (0x100 as i32 as u32 <= val && val <= 0xd7ff as i32 as u32
                            || 0xe000 as i32 as u32 <= val && val <= 0xfffd as i32 as u32
                            || 0x10000 as i32 as u32 <= val && val <= 0x10ffff as i32 as u32)
                            as i32
                    } == 0
                    {
                        xmlXPathErr(ctxt, XPATH_INVALID_CHAR_ERROR as i32);
                        return 0 as i32;
                    }
                    return val as i32;
                }
            }
        }
        (unsafe { *len = 0 as i32 });
        xmlXPathErr(ctxt, XPATH_ENCODING_ERROR as i32);
        return 0 as i32;
    } else {
        (unsafe { *len = 1 as i32 });
        return (unsafe { *cur }) as i32;
    };
}
#[no_mangle]
pub extern "C" fn xmlXPathParseNCName(mut ctxt: xmlXPathParserContextPtr) -> *mut xmlChar {
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut count: i32 = 0 as i32;
    if ctxt.is_null() || (unsafe { (*ctxt).cur }).is_null() {
        return 0 as *mut xmlChar;
    }
    in_0 = unsafe { (*ctxt).cur };
    if (unsafe { *in_0 }) as i32 >= 0x61 as i32 && (unsafe { *in_0 }) as i32 <= 0x7a as i32
        || (unsafe { *in_0 }) as i32 >= 0x41 as i32 && (unsafe { *in_0 }) as i32 <= 0x5a as i32
        || (unsafe { *in_0 }) as i32 == '_' as i32
    {
        in_0 = unsafe { in_0.offset(1) };
        while (unsafe { *in_0 }) as i32 >= 0x61 as i32 && (unsafe { *in_0 }) as i32 <= 0x7a as i32
            || (unsafe { *in_0 }) as i32 >= 0x41 as i32 && (unsafe { *in_0 }) as i32 <= 0x5a as i32
            || (unsafe { *in_0 }) as i32 >= 0x30 as i32 && (unsafe { *in_0 }) as i32 <= 0x39 as i32
            || (unsafe { *in_0 }) as i32 == '_' as i32
            || (unsafe { *in_0 }) as i32 == '.' as i32
            || (unsafe { *in_0 }) as i32 == '-' as i32
        {
            in_0 = unsafe { in_0.offset(1) };
        }
        if (unsafe { *in_0 }) as i32 == ' ' as i32
            || (unsafe { *in_0 }) as i32 == '>' as i32
            || (unsafe { *in_0 }) as i32 == '/' as i32
            || (unsafe { *in_0 }) as i32 == '[' as i32
            || (unsafe { *in_0 }) as i32 == ']' as i32
            || (unsafe { *in_0 }) as i32 == ':' as i32
            || (unsafe { *in_0 }) as i32 == '@' as i32
            || (unsafe { *in_0 }) as i32 == '*' as i32
        {
            count = (unsafe { in_0.offset_from((*ctxt).cur) }) as i64 as i32;
            if count == 0 as i32 {
                return 0 as *mut xmlChar;
            }
            ret = unsafe { xmlStrndup((*ctxt).cur, count) };
            let fresh207 = unsafe { &mut ((*ctxt).cur) };
            *fresh207 = in_0;
            return ret;
        }
    }
    return xmlXPathParseNameComplex(ctxt, 0 as i32);
}
extern "C" fn xmlXPathParseQName(
    mut ctxt: xmlXPathParserContextPtr,
    mut prefix: *mut *mut xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    (unsafe { *prefix = 0 as *mut xmlChar });
    ret = xmlXPathParseNCName(ctxt);
    if !ret.is_null() && (unsafe { *(*ctxt).cur }) as i32 == ':' as i32 {
        (unsafe { *prefix = ret });
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh208 = unsafe { &mut ((*ctxt).cur) };
            *fresh208 = unsafe { (*fresh208).offset(1) };
        } else {
        };
        ret = xmlXPathParseNCName(ctxt);
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXPathParseName(mut ctxt: xmlXPathParserContextPtr) -> *mut xmlChar {
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut count: size_t = 0 as i32 as size_t;
    if ctxt.is_null() || (unsafe { (*ctxt).cur }).is_null() {
        return 0 as *mut xmlChar;
    }
    in_0 = unsafe { (*ctxt).cur };
    if (unsafe { *in_0 }) as i32 >= 0x61 as i32 && (unsafe { *in_0 }) as i32 <= 0x7a as i32
        || (unsafe { *in_0 }) as i32 >= 0x41 as i32 && (unsafe { *in_0 }) as i32 <= 0x5a as i32
        || (unsafe { *in_0 }) as i32 == '_' as i32
        || (unsafe { *in_0 }) as i32 == ':' as i32
    {
        in_0 = unsafe { in_0.offset(1) };
        while (unsafe { *in_0 }) as i32 >= 0x61 as i32 && (unsafe { *in_0 }) as i32 <= 0x7a as i32
            || (unsafe { *in_0 }) as i32 >= 0x41 as i32 && (unsafe { *in_0 }) as i32 <= 0x5a as i32
            || (unsafe { *in_0 }) as i32 >= 0x30 as i32 && (unsafe { *in_0 }) as i32 <= 0x39 as i32
            || (unsafe { *in_0 }) as i32 == '_' as i32
            || (unsafe { *in_0 }) as i32 == '-' as i32
            || (unsafe { *in_0 }) as i32 == ':' as i32
            || (unsafe { *in_0 }) as i32 == '.' as i32
        {
            in_0 = unsafe { in_0.offset(1) };
        }
        if (unsafe { *in_0 }) as i32 > 0 as i32 && ((unsafe { *in_0 }) as i32) < 0x80 as i32 {
            count = (unsafe { in_0.offset_from((*ctxt).cur) }) as i64 as size_t;
            if count > 50000 as i32 as u64 {
                let fresh209 = unsafe { &mut ((*ctxt).cur) };
                *fresh209 = in_0;
                xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
                return 0 as *mut xmlChar;
            }
            ret = unsafe { xmlStrndup((*ctxt).cur, count as i32) };
            let fresh210 = unsafe { &mut ((*ctxt).cur) };
            *fresh210 = in_0;
            return ret;
        }
    }
    return xmlXPathParseNameComplex(ctxt, 1 as i32);
}
extern "C" fn xmlXPathParseNameComplex(
    mut ctxt: xmlXPathParserContextPtr,
    mut qualified: i32,
) -> *mut xmlChar {
    let mut buf: [xmlChar; 105] = [0; 105];
    let mut len: i32 = 0 as i32;
    let mut l: i32 = 0;
    let mut c: i32 = 0;
    c = xmlXPathCurrentChar(ctxt, &mut l);
    if c == ' ' as i32
        || c == '>' as i32
        || c == '/' as i32
        || c == '[' as i32
        || c == ']' as i32
        || c == '@' as i32
        || c == '*' as i32
        || !((if c < 0x100 as i32 {
            (0x41 as i32 <= c && c <= 0x5a as i32
                || 0x61 as i32 <= c && c <= 0x7a as i32
                || 0xc0 as i32 <= c && c <= 0xd6 as i32
                || 0xd8 as i32 <= c && c <= 0xf6 as i32
                || 0xf8 as i32 <= c) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
        }) != 0
            || (if c < 0x100 as i32 {
                0 as i32
            } else {
                (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                    || c == 0x3007 as i32
                    || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
            }) != 0)
            && c != '_' as i32
            && (qualified == 0 || c != ':' as i32)
    {
        return 0 as *mut xmlChar;
    }
    while c != ' ' as i32
        && c != '>' as i32
        && c != '/' as i32
        && ((if c < 0x100 as i32 {
            (0x41 as i32 <= c && c <= 0x5a as i32
                || 0x61 as i32 <= c && c <= 0x7a as i32
                || 0xc0 as i32 <= c && c <= 0xd6 as i32
                || 0xd8 as i32 <= c && c <= 0xf6 as i32
                || 0xf8 as i32 <= c) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
        }) != 0
            || (if c < 0x100 as i32 {
                0 as i32
            } else {
                (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                    || c == 0x3007 as i32
                    || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
            }) != 0
            || (if c < 0x100 as i32 {
                (0x30 as i32 <= c && c <= 0x39 as i32) as i32
            } else {
                unsafe { xmlCharInRange(c as u32, &xmlIsDigitGroup) }
            }) != 0
            || c == '.' as i32
            || c == '-' as i32
            || c == '_' as i32
            || qualified != 0 && c == ':' as i32
            || (if c < 0x100 as i32 {
                0 as i32
            } else {
                unsafe { xmlCharInRange(c as u32, &xmlIsCombiningGroup) }
            }) != 0
            || (if c < 0x100 as i32 {
                (c == 0xb7 as i32) as i32
            } else {
                unsafe { xmlCharInRange(c as u32, &xmlIsExtenderGroup) }
            }) != 0)
    {
        if l == 1 as i32 {
            let fresh211 = len;
            len = len + 1;
            buf[fresh211 as usize] = c as xmlChar;
        } else {
            len += unsafe { xmlCopyChar(l, &mut *buf.as_mut_ptr().offset(len as isize), c) };
        }
        let fresh212 = unsafe { &mut ((*ctxt).cur) };
        *fresh212 = unsafe { (*fresh212).offset(l as isize) };
        c = xmlXPathCurrentChar(ctxt, &mut l);
        if len >= 100 as i32 {
            let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
            let mut max: i32 = len * 2 as i32;
            if len > 50000 as i32 {
                xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
                return 0 as *mut xmlChar;
            }
            buffer = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
                (max as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) }) as *mut xmlChar;
            if buffer.is_null() {
                xmlXPathErr(ctxt, XPATH_MEMORY_ERROR as i32);
                return 0 as *mut xmlChar;
            }
            (unsafe { memcpy(
                buffer as *mut libc::c_void,
                buf.as_mut_ptr() as *const libc::c_void,
                len as u64,
            ) });
            while (if c < 0x100 as i32 {
                (0x41 as i32 <= c && c <= 0x5a as i32
                    || 0x61 as i32 <= c && c <= 0x7a as i32
                    || 0xc0 as i32 <= c && c <= 0xd6 as i32
                    || 0xd8 as i32 <= c && c <= 0xf6 as i32
                    || 0xf8 as i32 <= c) as i32
            } else {
                unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
            }) != 0
                || (if c < 0x100 as i32 {
                    0 as i32
                } else {
                    (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                        || c == 0x3007 as i32
                        || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
                }) != 0
                || (if c < 0x100 as i32 {
                    (0x30 as i32 <= c && c <= 0x39 as i32) as i32
                } else {
                    unsafe { xmlCharInRange(c as u32, &xmlIsDigitGroup) }
                }) != 0
                || c == '.' as i32
                || c == '-' as i32
                || c == '_' as i32
                || qualified != 0 && c == ':' as i32
                || (if c < 0x100 as i32 {
                    0 as i32
                } else {
                    unsafe { xmlCharInRange(c as u32, &xmlIsCombiningGroup) }
                }) != 0
                || (if c < 0x100 as i32 {
                    (c == 0xb7 as i32) as i32
                } else {
                    unsafe { xmlCharInRange(c as u32, &xmlIsExtenderGroup) }
                }) != 0
            {
                if len + 10 as i32 > max {
                    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                    if max > 50000 as i32 {
                        (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
                        xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
                        return 0 as *mut xmlChar;
                    }
                    max *= 2 as i32;
                    tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                        buffer as *mut libc::c_void,
                        (max as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
                    ) }) as *mut xmlChar;
                    if tmp.is_null() {
                        (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
                        xmlXPathErr(ctxt, XPATH_MEMORY_ERROR as i32);
                        return 0 as *mut xmlChar;
                    }
                    buffer = tmp;
                }
                if l == 1 as i32 {
                    let fresh213 = len;
                    len = len + 1;
                    (unsafe { *buffer.offset(fresh213 as isize) = c as xmlChar });
                } else {
                    len += unsafe { xmlCopyChar(l, &mut *buffer.offset(len as isize), c) };
                }
                let fresh214 = unsafe { &mut ((*ctxt).cur) };
                *fresh214 = unsafe { (*fresh214).offset(l as isize) };
                c = xmlXPathCurrentChar(ctxt, &mut l);
            }
            (unsafe { *buffer.offset(len as isize) = 0 as i32 as xmlChar });
            return buffer;
        }
    }
    if len == 0 as i32 {
        return 0 as *mut xmlChar;
    }
    return unsafe { xmlStrndup(buf.as_mut_ptr(), len) };
}
#[no_mangle]
pub extern "C" fn xmlXPathStringEvalNumber(mut str: *const xmlChar) -> f64 {
    let mut cur: *const xmlChar = str;
    let mut ret: f64 = 0.;
    let mut ok: i32 = 0 as i32;
    let mut isneg: i32 = 0 as i32;
    let mut exponent: i32 = 0 as i32;
    let mut is_exponent_negative: i32 = 0 as i32;
    let mut tmp: u64 = 0 as i32 as u64;
    let mut temp: f64 = 0.;
    if cur.is_null() {
        return 0 as i32 as f64;
    }
    while (unsafe { *cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
        || (unsafe { *cur }) as i32 == 0xd as i32
    {
        cur = unsafe { cur.offset(1) };
    }
    if (unsafe { *cur }) as i32 != '.' as i32
        && (((unsafe { *cur }) as i32) < '0' as i32 || (unsafe { *cur }) as i32 > '9' as i32)
        && (unsafe { *cur }) as i32 != '-' as i32
    {
        return unsafe { xmlXPathNAN };
    }
    if (unsafe { *cur }) as i32 == '-' as i32 {
        isneg = 1 as i32;
        cur = unsafe { cur.offset(1) };
    }
    ret = 0 as i32 as f64;
    while (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
        ret = ret * 10 as i32 as f64;
        tmp = ((unsafe { *cur }) as i32 - '0' as i32) as u64;
        ok = 1 as i32;
        cur = unsafe { cur.offset(1) };
        temp = tmp as f64;
        ret = ret + temp;
    }
    if (unsafe { *cur }) as i32 == '.' as i32 {
        let mut v: i32 = 0;
        let mut frac: i32 = 0 as i32;
        let mut max: i32 = 0;
        let mut fraction: f64 = 0 as i32 as f64;
        cur = unsafe { cur.offset(1) };
        if (((unsafe { *cur }) as i32) < '0' as i32 || (unsafe { *cur }) as i32 > '9' as i32) && ok == 0 {
            return unsafe { xmlXPathNAN };
        }
        while (unsafe { *cur }) as i32 == '0' as i32 {
            frac = frac + 1 as i32;
            cur = unsafe { cur.offset(1) };
        }
        max = frac + 20 as i32;
        while (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 && frac < max {
            v = (unsafe { *cur }) as i32 - '0' as i32;
            fraction = fraction * 10 as i32 as f64 + v as f64;
            frac = frac + 1 as i32;
            cur = unsafe { cur.offset(1) };
        }
        fraction /= unsafe { pow(10.0f64, frac as f64) };
        ret = ret + fraction;
        while (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
            cur = unsafe { cur.offset(1) };
        }
    }
    if (unsafe { *cur }) as i32 == 'e' as i32 || (unsafe { *cur }) as i32 == 'E' as i32 {
        cur = unsafe { cur.offset(1) };
        if (unsafe { *cur }) as i32 == '-' as i32 {
            is_exponent_negative = 1 as i32;
            cur = unsafe { cur.offset(1) };
        } else if (unsafe { *cur }) as i32 == '+' as i32 {
            cur = unsafe { cur.offset(1) };
        }
        while (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
            if exponent < 1000000 as i32 {
                exponent = exponent * 10 as i32 + ((unsafe { *cur }) as i32 - '0' as i32);
            }
            cur = unsafe { cur.offset(1) };
        }
    }
    while (unsafe { *cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
        || (unsafe { *cur }) as i32 == 0xd as i32
    {
        cur = unsafe { cur.offset(1) };
    }
    if (unsafe { *cur }) as i32 != 0 as i32 {
        return unsafe { xmlXPathNAN };
    }
    if isneg != 0 {
        ret = -ret;
    }
    if is_exponent_negative != 0 {
        exponent = -exponent;
    }
    ret *= unsafe { pow(10.0f64, exponent as f64) };
    return ret;
}
extern "C" fn xmlXPathCompNumber(mut ctxt: xmlXPathParserContextPtr) {
    let mut ret: f64 = 0.0f64;
    let mut ok: i32 = 0 as i32;
    let mut exponent: i32 = 0 as i32;
    let mut is_exponent_negative: i32 = 0 as i32;
    let mut num: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut tmp: u64 = 0 as i32 as u64;
    let mut temp: f64 = 0.;
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return;
    }
    if (unsafe { *(*ctxt).cur }) as i32 != '.' as i32
        && (((unsafe { *(*ctxt).cur }) as i32) < '0' as i32 || (unsafe { *(*ctxt).cur }) as i32 > '9' as i32)
    {
        xmlXPathErr(ctxt, XPATH_NUMBER_ERROR as i32);
        return;
    }
    ret = 0 as i32 as f64;
    while (unsafe { *(*ctxt).cur }) as i32 >= '0' as i32 && (unsafe { *(*ctxt).cur }) as i32 <= '9' as i32 {
        ret = ret * 10 as i32 as f64;
        tmp = ((unsafe { *(*ctxt).cur }) as i32 - '0' as i32) as u64;
        ok = 1 as i32;
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh215 = unsafe { &mut ((*ctxt).cur) };
            *fresh215 = unsafe { (*fresh215).offset(1) };
        } else {
        };
        temp = tmp as f64;
        ret = ret + temp;
    }
    if (unsafe { *(*ctxt).cur }) as i32 == '.' as i32 {
        let mut v: i32 = 0;
        let mut frac: i32 = 0 as i32;
        let mut max: i32 = 0;
        let mut fraction: f64 = 0 as i32 as f64;
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh216 = unsafe { &mut ((*ctxt).cur) };
            *fresh216 = unsafe { (*fresh216).offset(1) };
        } else {
        };
        if (((unsafe { *(*ctxt).cur }) as i32) < '0' as i32 || (unsafe { *(*ctxt).cur }) as i32 > '9' as i32) && ok == 0 {
            xmlXPathErr(ctxt, XPATH_NUMBER_ERROR as i32);
            return;
        }
        while (unsafe { *(*ctxt).cur }) as i32 == '0' as i32 {
            frac = frac + 1 as i32;
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh217 = unsafe { &mut ((*ctxt).cur) };
                *fresh217 = unsafe { (*fresh217).offset(1) };
            } else {
            };
        }
        max = frac + 20 as i32;
        while (unsafe { *(*ctxt).cur }) as i32 >= '0' as i32 && (unsafe { *(*ctxt).cur }) as i32 <= '9' as i32 && frac < max {
            v = (unsafe { *(*ctxt).cur }) as i32 - '0' as i32;
            fraction = fraction * 10 as i32 as f64 + v as f64;
            frac = frac + 1 as i32;
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh218 = unsafe { &mut ((*ctxt).cur) };
                *fresh218 = unsafe { (*fresh218).offset(1) };
            } else {
            };
        }
        fraction /= unsafe { pow(10.0f64, frac as f64) };
        ret = ret + fraction;
        while (unsafe { *(*ctxt).cur }) as i32 >= '0' as i32 && (unsafe { *(*ctxt).cur }) as i32 <= '9' as i32 {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh219 = unsafe { &mut ((*ctxt).cur) };
                *fresh219 = unsafe { (*fresh219).offset(1) };
            } else {
            };
        }
    }
    if (unsafe { *(*ctxt).cur }) as i32 == 'e' as i32 || (unsafe { *(*ctxt).cur }) as i32 == 'E' as i32 {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh220 = unsafe { &mut ((*ctxt).cur) };
            *fresh220 = unsafe { (*fresh220).offset(1) };
        } else {
        };
        if (unsafe { *(*ctxt).cur }) as i32 == '-' as i32 {
            is_exponent_negative = 1 as i32;
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh221 = unsafe { &mut ((*ctxt).cur) };
                *fresh221 = unsafe { (*fresh221).offset(1) };
            } else {
            };
        } else if (unsafe { *(*ctxt).cur }) as i32 == '+' as i32 {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh222 = unsafe { &mut ((*ctxt).cur) };
                *fresh222 = unsafe { (*fresh222).offset(1) };
            } else {
            };
        }
        while (unsafe { *(*ctxt).cur }) as i32 >= '0' as i32 && (unsafe { *(*ctxt).cur }) as i32 <= '9' as i32 {
            if exponent < 1000000 as i32 {
                exponent = exponent * 10 as i32 + ((unsafe { *(*ctxt).cur }) as i32 - '0' as i32);
            }
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh223 = unsafe { &mut ((*ctxt).cur) };
                *fresh223 = unsafe { (*fresh223).offset(1) };
            } else {
            };
        }
        if is_exponent_negative != 0 {
            exponent = -exponent;
        }
        ret *= unsafe { pow(10.0f64, exponent as f64) };
    }
    num = xmlXPathCacheNewFloat(unsafe { (*ctxt).context }, ret);
    if num.is_null() {
        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
    } else if xmlXPathCompExprAdd(
        ctxt,
        unsafe { (*(*ctxt).comp).last },
        -(1 as i32),
        XPATH_OP_VALUE,
        XPATH_NUMBER as i32,
        0 as i32,
        0 as i32,
        num as *mut libc::c_void,
        0 as *mut libc::c_void,
    ) == -(1 as i32)
    {
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, num);
    }
}
extern "C" fn xmlXPathParseLiteral(mut ctxt: xmlXPathParserContextPtr) -> *mut xmlChar {
    let mut q: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe { *(*ctxt).cur }) as i32 == '"' as i32 {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh224 = unsafe { &mut ((*ctxt).cur) };
            *fresh224 = unsafe { (*fresh224).offset(1) };
        } else {
        };
        q = unsafe { (*ctxt).cur };
        while (0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            || 0x20 as i32 <= (unsafe { *(*ctxt).cur }) as i32)
            && (unsafe { *(*ctxt).cur }) as i32 != '"' as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh225 = unsafe { &mut ((*ctxt).cur) };
                *fresh225 = unsafe { (*fresh225).offset(1) };
            } else {
            };
        }
        if !(0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            || 0x20 as i32 <= (unsafe { *(*ctxt).cur }) as i32)
        {
            xmlXPathErr(ctxt, XPATH_UNFINISHED_LITERAL_ERROR as i32);
            return 0 as *mut xmlChar;
        } else {
            ret = unsafe { xmlStrndup(q, ((*ctxt).cur).offset_from(q) as i64 as i32) };
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh226 = unsafe { &mut ((*ctxt).cur) };
                *fresh226 = unsafe { (*fresh226).offset(1) };
            } else {
            };
        }
    } else if (unsafe { *(*ctxt).cur }) as i32 == '\'' as i32 {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh227 = unsafe { &mut ((*ctxt).cur) };
            *fresh227 = unsafe { (*fresh227).offset(1) };
        } else {
        };
        q = unsafe { (*ctxt).cur };
        while (0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            || 0x20 as i32 <= (unsafe { *(*ctxt).cur }) as i32)
            && (unsafe { *(*ctxt).cur }) as i32 != '\'' as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh228 = unsafe { &mut ((*ctxt).cur) };
                *fresh228 = unsafe { (*fresh228).offset(1) };
            } else {
            };
        }
        if !(0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            || 0x20 as i32 <= (unsafe { *(*ctxt).cur }) as i32)
        {
            xmlXPathErr(ctxt, XPATH_UNFINISHED_LITERAL_ERROR as i32);
            return 0 as *mut xmlChar;
        } else {
            ret = unsafe { xmlStrndup(q, ((*ctxt).cur).offset_from(q) as i64 as i32) };
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh229 = unsafe { &mut ((*ctxt).cur) };
                *fresh229 = unsafe { (*fresh229).offset(1) };
            } else {
            };
        }
    } else {
        xmlXPathErr(ctxt, XPATH_START_LITERAL_ERROR as i32);
        return 0 as *mut xmlChar;
    }
    return ret;
}
extern "C" fn xmlXPathCompLiteral(mut ctxt: xmlXPathParserContextPtr) {
    let mut q: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut lit: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if (unsafe { *(*ctxt).cur }) as i32 == '"' as i32 {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh230 = unsafe { &mut ((*ctxt).cur) };
            *fresh230 = unsafe { (*fresh230).offset(1) };
        } else {
        };
        q = unsafe { (*ctxt).cur };
        while (0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            || 0x20 as i32 <= (unsafe { *(*ctxt).cur }) as i32)
            && (unsafe { *(*ctxt).cur }) as i32 != '"' as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh231 = unsafe { &mut ((*ctxt).cur) };
                *fresh231 = unsafe { (*fresh231).offset(1) };
            } else {
            };
        }
        if !(0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            || 0x20 as i32 <= (unsafe { *(*ctxt).cur }) as i32)
        {
            xmlXPathErr(ctxt, XPATH_UNFINISHED_LITERAL_ERROR as i32);
            return;
        } else {
            ret = unsafe { xmlStrndup(q, ((*ctxt).cur).offset_from(q) as i64 as i32) };
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh232 = unsafe { &mut ((*ctxt).cur) };
                *fresh232 = unsafe { (*fresh232).offset(1) };
            } else {
            };
        }
    } else if (unsafe { *(*ctxt).cur }) as i32 == '\'' as i32 {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh233 = unsafe { &mut ((*ctxt).cur) };
            *fresh233 = unsafe { (*fresh233).offset(1) };
        } else {
        };
        q = unsafe { (*ctxt).cur };
        while (0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            || 0x20 as i32 <= (unsafe { *(*ctxt).cur }) as i32)
            && (unsafe { *(*ctxt).cur }) as i32 != '\'' as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh234 = unsafe { &mut ((*ctxt).cur) };
                *fresh234 = unsafe { (*fresh234).offset(1) };
            } else {
            };
        }
        if !(0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            || 0x20 as i32 <= (unsafe { *(*ctxt).cur }) as i32)
        {
            xmlXPathErr(ctxt, XPATH_UNFINISHED_LITERAL_ERROR as i32);
            return;
        } else {
            ret = unsafe { xmlStrndup(q, ((*ctxt).cur).offset_from(q) as i64 as i32) };
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh235 = unsafe { &mut ((*ctxt).cur) };
                *fresh235 = unsafe { (*fresh235).offset(1) };
            } else {
            };
        }
    } else {
        xmlXPathErr(ctxt, XPATH_START_LITERAL_ERROR as i32);
        return;
    }
    if ret.is_null() {
        return;
    }
    lit = xmlXPathCacheNewString(unsafe { (*ctxt).context }, ret);
    if lit.is_null() {
        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
    } else if xmlXPathCompExprAdd(
        ctxt,
        unsafe { (*(*ctxt).comp).last },
        -(1 as i32),
        XPATH_OP_VALUE,
        XPATH_STRING as i32,
        0 as i32,
        0 as i32,
        lit as *mut libc::c_void,
        0 as *mut libc::c_void,
    ) == -(1 as i32)
    {
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, lit);
    }
    (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
}
extern "C" fn xmlXPathCompVariableReference(mut ctxt: xmlXPathParserContextPtr) {
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh236 = unsafe { &mut ((*ctxt).cur) };
            *fresh236 = unsafe { (*fresh236).offset(1) };
        } else {
        };
    }
    if (unsafe { *(*ctxt).cur }) as i32 != '$' as i32 {
        xmlXPathErr(ctxt, XPATH_VARIABLE_REF_ERROR as i32);
        return;
    }
    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
        let fresh237 = unsafe { &mut ((*ctxt).cur) };
        *fresh237 = unsafe { (*fresh237).offset(1) };
    } else {
    };
    name = xmlXPathParseQName(ctxt, &mut prefix);
    if name.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
        xmlXPathErr(ctxt, XPATH_VARIABLE_REF_ERROR as i32);
        return;
    }
    (unsafe { (*(*ctxt).comp).last = -(1 as i32) });
    if xmlXPathCompExprAdd(
        ctxt,
        unsafe { (*(*ctxt).comp).last },
        -(1 as i32),
        XPATH_OP_VARIABLE,
        0 as i32,
        0 as i32,
        0 as i32,
        name as *mut libc::c_void,
        prefix as *mut libc::c_void,
    ) == -(1 as i32)
    {
        (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
        (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh238 = unsafe { &mut ((*ctxt).cur) };
            *fresh238 = unsafe { (*fresh238).offset(1) };
        } else {
        };
    }
    if !(unsafe { (*ctxt).context }).is_null() && (unsafe { (*(*ctxt).context).flags }) & (1 as i32) << 1 as i32 != 0 {
        xmlXPathErr(ctxt, XPATH_FORBID_VARIABLE_ERROR as i32);
        return;
    }
}
#[no_mangle]
pub extern "C" fn xmlXPathIsNodeType(mut name: *const xmlChar) -> i32 {
    if name.is_null() {
        return 0 as i32;
    }
    if (unsafe { xmlStrEqual(name, b"node\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
        return 1 as i32;
    }
    if (unsafe { xmlStrEqual(name, b"text\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
        return 1 as i32;
    }
    if (unsafe { xmlStrEqual(name, b"comment\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
        return 1 as i32;
    }
    if (unsafe { xmlStrEqual(
        name,
        b"processing-instruction\0" as *const u8 as *const i8 as *mut xmlChar,
    ) }) != 0
    {
        return 1 as i32;
    }
    return 0 as i32;
}
extern "C" fn xmlXPathCompFunctionCall(mut ctxt: xmlXPathParserContextPtr) {
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    let mut nbargs: i32 = 0 as i32;
    let mut sort: i32 = 1 as i32;
    name = xmlXPathParseQName(ctxt, &mut prefix);
    if name.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
        xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
        return;
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh239 = unsafe { &mut ((*ctxt).cur) };
            *fresh239 = unsafe { (*fresh239).offset(1) };
        } else {
        };
    }
    if (unsafe { *(*ctxt).cur }) as i32 != '(' as i32 {
        (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
        (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
        xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
        return;
    }
    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
        let fresh240 = unsafe { &mut ((*ctxt).cur) };
        *fresh240 = unsafe { (*fresh240).offset(1) };
    } else {
    };
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh241 = unsafe { &mut ((*ctxt).cur) };
            *fresh241 = unsafe { (*fresh241).offset(1) };
        } else {
        };
    }
    if prefix.is_null()
        && (unsafe { *name.offset(0 as i32 as isize) }) as i32 == 'c' as i32
        && (unsafe { xmlStrEqual(name, b"count\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0
    {
        sort = 0 as i32;
    }
    (unsafe { (*(*ctxt).comp).last = -(1 as i32) });
    if (unsafe { *(*ctxt).cur }) as i32 != ')' as i32 {
        while (unsafe { *(*ctxt).cur }) as i32 != 0 as i32 {
            let mut op1: i32 = unsafe { (*(*ctxt).comp).last };
            (unsafe { (*(*ctxt).comp).last = -(1 as i32) });
            xmlXPathCompileExpr(ctxt, sort);
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
                (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
                return;
            }
            xmlXPathCompExprAdd(
                ctxt,
                op1,
                unsafe { (*(*ctxt).comp).last },
                XPATH_OP_ARG,
                0 as i32,
                0 as i32,
                0 as i32,
                0 as *mut libc::c_void,
                0 as *mut libc::c_void,
            );
            nbargs += 1;
            if (unsafe { *(*ctxt).cur }) as i32 == ')' as i32 {
                break;
            }
            if (unsafe { *(*ctxt).cur }) as i32 != ',' as i32 {
                (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
                (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
                xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
                return;
            }
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh242 = unsafe { &mut ((*ctxt).cur) };
                *fresh242 = unsafe { (*fresh242).offset(1) };
            } else {
            };
            while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            {
                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                    let fresh243 = unsafe { &mut ((*ctxt).cur) };
                    *fresh243 = unsafe { (*fresh243).offset(1) };
                } else {
                };
            }
        }
    }
    if xmlXPathCompExprAdd(
        ctxt,
        unsafe { (*(*ctxt).comp).last },
        -(1 as i32),
        XPATH_OP_FUNCTION,
        nbargs,
        0 as i32,
        0 as i32,
        name as *mut libc::c_void,
        prefix as *mut libc::c_void,
    ) == -(1 as i32)
    {
        (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
        (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
    }
    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
        let fresh244 = unsafe { &mut ((*ctxt).cur) };
        *fresh244 = unsafe { (*fresh244).offset(1) };
    } else {
    };
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh245 = unsafe { &mut ((*ctxt).cur) };
            *fresh245 = unsafe { (*fresh245).offset(1) };
        } else {
        };
    }
}
extern "C" fn xmlXPathCompPrimaryExpr(mut ctxt: xmlXPathParserContextPtr) {
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh246 = unsafe { &mut ((*ctxt).cur) };
            *fresh246 = unsafe { (*fresh246).offset(1) };
        } else {
        };
    }
    if (unsafe { *(*ctxt).cur }) as i32 == '$' as i32 {
        xmlXPathCompVariableReference(ctxt);
    } else if (unsafe { *(*ctxt).cur }) as i32 == '(' as i32 {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh247 = unsafe { &mut ((*ctxt).cur) };
            *fresh247 = unsafe { (*fresh247).offset(1) };
        } else {
        };
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh248 = unsafe { &mut ((*ctxt).cur) };
                *fresh248 = unsafe { (*fresh248).offset(1) };
            } else {
            };
        }
        xmlXPathCompileExpr(ctxt, 1 as i32);
        if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
            return;
        }
        if (unsafe { *(*ctxt).cur }) as i32 != ')' as i32 {
            xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
            return;
        }
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh249 = unsafe { &mut ((*ctxt).cur) };
            *fresh249 = unsafe { (*fresh249).offset(1) };
        } else {
        };
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh250 = unsafe { &mut ((*ctxt).cur) };
                *fresh250 = unsafe { (*fresh250).offset(1) };
            } else {
            };
        }
    } else if 0x30 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0x39 as i32
        || (unsafe { *(*ctxt).cur }) as i32 == '.' as i32
            && (0x30 as i32 <= (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32
                && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 <= 0x39 as i32)
    {
        xmlXPathCompNumber(ctxt);
    } else if (unsafe { *(*ctxt).cur }) as i32 == '\'' as i32 || (unsafe { *(*ctxt).cur }) as i32 == '"' as i32 {
        xmlXPathCompLiteral(ctxt);
    } else {
        xmlXPathCompFunctionCall(ctxt);
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh251 = unsafe { &mut ((*ctxt).cur) };
            *fresh251 = unsafe { (*fresh251).offset(1) };
        } else {
        };
    }
}
extern "C" fn xmlXPathCompFilterExpr(mut ctxt: xmlXPathParserContextPtr) {
    xmlXPathCompPrimaryExpr(ctxt);
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return;
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh252 = unsafe { &mut ((*ctxt).cur) };
            *fresh252 = unsafe { (*fresh252).offset(1) };
        } else {
        };
    }
    while (unsafe { *(*ctxt).cur }) as i32 == '[' as i32 {
        xmlXPathCompPredicate(ctxt, 1 as i32);
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh253 = unsafe { &mut ((*ctxt).cur) };
                *fresh253 = unsafe { (*fresh253).offset(1) };
            } else {
            };
        }
    }
}
extern "C" fn xmlXPathScanName(mut ctxt: xmlXPathParserContextPtr) -> *mut xmlChar {
    let mut len: i32 = 0 as i32;
    let mut l: i32 = 0;
    let mut c: i32 = 0;
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    cur = unsafe { (*ctxt).cur };
    c = xmlXPathCurrentChar(ctxt, &mut l);
    if c == ' ' as i32
        || c == '>' as i32
        || c == '/' as i32
        || !((if c < 0x100 as i32 {
            (0x41 as i32 <= c && c <= 0x5a as i32
                || 0x61 as i32 <= c && c <= 0x7a as i32
                || 0xc0 as i32 <= c && c <= 0xd6 as i32
                || 0xd8 as i32 <= c && c <= 0xf6 as i32
                || 0xf8 as i32 <= c) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
        }) != 0
            || (if c < 0x100 as i32 {
                0 as i32
            } else {
                (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                    || c == 0x3007 as i32
                    || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
            }) != 0)
            && c != '_' as i32
            && c != ':' as i32
    {
        return 0 as *mut xmlChar;
    }
    while c != ' ' as i32
        && c != '>' as i32
        && c != '/' as i32
        && ((if c < 0x100 as i32 {
            (0x41 as i32 <= c && c <= 0x5a as i32
                || 0x61 as i32 <= c && c <= 0x7a as i32
                || 0xc0 as i32 <= c && c <= 0xd6 as i32
                || 0xd8 as i32 <= c && c <= 0xf6 as i32
                || 0xf8 as i32 <= c) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
        }) != 0
            || (if c < 0x100 as i32 {
                0 as i32
            } else {
                (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                    || c == 0x3007 as i32
                    || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
            }) != 0
            || (if c < 0x100 as i32 {
                (0x30 as i32 <= c && c <= 0x39 as i32) as i32
            } else {
                unsafe { xmlCharInRange(c as u32, &xmlIsDigitGroup) }
            }) != 0
            || c == '.' as i32
            || c == '-' as i32
            || c == '_' as i32
            || c == ':' as i32
            || (if c < 0x100 as i32 {
                0 as i32
            } else {
                unsafe { xmlCharInRange(c as u32, &xmlIsCombiningGroup) }
            }) != 0
            || (if c < 0x100 as i32 {
                (c == 0xb7 as i32) as i32
            } else {
                unsafe { xmlCharInRange(c as u32, &xmlIsExtenderGroup) }
            }) != 0)
    {
        len += l;
        let fresh254 = unsafe { &mut ((*ctxt).cur) };
        *fresh254 = unsafe { (*fresh254).offset(l as isize) };
        c = xmlXPathCurrentChar(ctxt, &mut l);
    }
    ret = unsafe { xmlStrndup(cur, ((*ctxt).cur).offset_from(cur) as i64 as i32) };
    let fresh255 = unsafe { &mut ((*ctxt).cur) };
    *fresh255 = cur;
    return ret;
}
extern "C" fn xmlXPathCompPathExpr(mut ctxt: xmlXPathParserContextPtr) {
    let mut lc: i32 = 1 as i32;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh256 = unsafe { &mut ((*ctxt).cur) };
            *fresh256 = unsafe { (*fresh256).offset(1) };
        } else {
        };
    }
    if (unsafe { *(*ctxt).cur }) as i32 == '$' as i32
        || (unsafe { *(*ctxt).cur }) as i32 == '(' as i32
        || 0x30 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0x39 as i32
        || (unsafe { *(*ctxt).cur }) as i32 == '\'' as i32
        || (unsafe { *(*ctxt).cur }) as i32 == '"' as i32
        || (unsafe { *(*ctxt).cur }) as i32 == '.' as i32
            && (0x30 as i32 <= (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32
                && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 <= 0x39 as i32)
    {
        lc = 0 as i32;
    } else if (unsafe { *(*ctxt).cur }) as i32 == '*' as i32 {
        lc = 1 as i32;
    } else if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32 {
        lc = 1 as i32;
    } else if (unsafe { *(*ctxt).cur }) as i32 == '@' as i32 {
        lc = 1 as i32;
    } else if (unsafe { *(*ctxt).cur }) as i32 == '.' as i32 {
        lc = 1 as i32;
    } else {
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh257 = unsafe { &mut ((*ctxt).cur) };
                *fresh257 = unsafe { (*fresh257).offset(1) };
            } else {
            };
        }
        name = xmlXPathScanName(ctxt);
        if !name.is_null()
            && !(unsafe { xmlStrstr(name, b"::\0" as *const u8 as *const i8 as *mut xmlChar) }).is_null()
        {
            lc = 1 as i32;
            (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
        } else if !name.is_null() {
            let mut len: i32 = unsafe { xmlStrlen(name) };
            while (unsafe { *((*ctxt).cur).offset(len as isize) }) as i32 != 0 as i32 {
                if (unsafe { *((*ctxt).cur).offset(len as isize) }) as i32 == '/' as i32 {
                    lc = 1 as i32;
                    break;
                } else if (unsafe { *((*ctxt).cur).offset(len as isize) }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *((*ctxt).cur).offset(len as isize) }) as i32
                        && (unsafe { *((*ctxt).cur).offset(len as isize) }) as i32 <= 0xa as i32
                    || (unsafe { *((*ctxt).cur).offset(len as isize) }) as i32 == 0xd as i32
                {
                    len += 1;
                } else if (unsafe { *((*ctxt).cur).offset(len as isize) }) as i32 == ':' as i32 {
                    lc = 1 as i32;
                    break;
                } else if (unsafe { *((*ctxt).cur).offset(len as isize) }) as i32 == '(' as i32 {
                    if xmlXPathIsNodeType(name) != 0 {
                        lc = 1 as i32;
                    } else {
                        lc = 0 as i32;
                    }
                    break;
                } else if (unsafe { *((*ctxt).cur).offset(len as isize) }) as i32 == '[' as i32 {
                    lc = 1 as i32;
                    break;
                } else if (unsafe { *((*ctxt).cur).offset(len as isize) }) as i32 == '<' as i32
                    || (unsafe { *((*ctxt).cur).offset(len as isize) }) as i32 == '>' as i32
                    || (unsafe { *((*ctxt).cur).offset(len as isize) }) as i32 == '=' as i32
                {
                    lc = 1 as i32;
                    break;
                } else {
                    lc = 1 as i32;
                    break;
                }
            }
            if (unsafe { *((*ctxt).cur).offset(len as isize) }) as i32 == 0 as i32 {
                lc = 1 as i32;
            }
            (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
        } else {
            xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
            return;
        }
    }
    if lc != 0 {
        if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32 {
            xmlXPathCompExprAdd(
                ctxt,
                -(1 as i32),
                -(1 as i32),
                XPATH_OP_ROOT,
                0 as i32,
                0 as i32,
                0 as i32,
                0 as *mut libc::c_void,
                0 as *mut libc::c_void,
            );
        } else {
            xmlXPathCompExprAdd(
                ctxt,
                -(1 as i32),
                -(1 as i32),
                XPATH_OP_NODE,
                0 as i32,
                0 as i32,
                0 as i32,
                0 as *mut libc::c_void,
                0 as *mut libc::c_void,
            );
        }
        xmlXPathCompLocationPath(ctxt);
    } else {
        xmlXPathCompFilterExpr(ctxt);
        if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
            return;
        }
        if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32
            && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32
        {
            let fresh258 = unsafe { &mut ((*ctxt).cur) };
            *fresh258 = unsafe { (*fresh258).offset(2 as i32 as isize) };
            while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            {
                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                    let fresh259 = unsafe { &mut ((*ctxt).cur) };
                    *fresh259 = unsafe { (*fresh259).offset(1) };
                } else {
                };
            }
            xmlXPathCompExprAdd(
                ctxt,
                unsafe { (*(*ctxt).comp).last },
                -(1 as i32),
                XPATH_OP_COLLECT,
                AXIS_DESCENDANT_OR_SELF as i32,
                NODE_TEST_TYPE as i32,
                NODE_TYPE_NODE as i32,
                0 as *mut libc::c_void,
                0 as *mut libc::c_void,
            );
            xmlXPathCompRelativeLocationPath(ctxt);
        } else if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32 {
            xmlXPathCompRelativeLocationPath(ctxt);
        }
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh260 = unsafe { &mut ((*ctxt).cur) };
            *fresh260 = unsafe { (*fresh260).offset(1) };
        } else {
        };
    }
}
extern "C" fn xmlXPathCompUnionExpr(mut ctxt: xmlXPathParserContextPtr) {
    xmlXPathCompPathExpr(ctxt);
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return;
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh261 = unsafe { &mut ((*ctxt).cur) };
            *fresh261 = unsafe { (*fresh261).offset(1) };
        } else {
        };
    }
    while (unsafe { *(*ctxt).cur }) as i32 == '|' as i32 {
        let mut op1: i32 = unsafe { (*(*ctxt).comp).last };
        xmlXPathCompExprAdd(
            ctxt,
            -(1 as i32),
            -(1 as i32),
            XPATH_OP_NODE,
            0 as i32,
            0 as i32,
            0 as i32,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
        );
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh262 = unsafe { &mut ((*ctxt).cur) };
            *fresh262 = unsafe { (*fresh262).offset(1) };
        } else {
        };
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh263 = unsafe { &mut ((*ctxt).cur) };
                *fresh263 = unsafe { (*fresh263).offset(1) };
            } else {
            };
        }
        xmlXPathCompPathExpr(ctxt);
        xmlXPathCompExprAdd(
            ctxt,
            op1,
            unsafe { (*(*ctxt).comp).last },
            XPATH_OP_UNION,
            0 as i32,
            0 as i32,
            0 as i32,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
        );
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh264 = unsafe { &mut ((*ctxt).cur) };
                *fresh264 = unsafe { (*fresh264).offset(1) };
            } else {
            };
        }
    }
}
extern "C" fn xmlXPathCompUnaryExpr(mut ctxt: xmlXPathParserContextPtr) {
    let mut minus: i32 = 0 as i32;
    let mut found: i32 = 0 as i32;
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh265 = unsafe { &mut ((*ctxt).cur) };
            *fresh265 = unsafe { (*fresh265).offset(1) };
        } else {
        };
    }
    while (unsafe { *(*ctxt).cur }) as i32 == '-' as i32 {
        minus = 1 as i32 - minus;
        found = 1 as i32;
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh266 = unsafe { &mut ((*ctxt).cur) };
            *fresh266 = unsafe { (*fresh266).offset(1) };
        } else {
        };
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh267 = unsafe { &mut ((*ctxt).cur) };
                *fresh267 = unsafe { (*fresh267).offset(1) };
            } else {
            };
        }
    }
    xmlXPathCompUnionExpr(ctxt);
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return;
    }
    if found != 0 {
        if minus != 0 {
            xmlXPathCompExprAdd(
                ctxt,
                unsafe { (*(*ctxt).comp).last },
                -(1 as i32),
                XPATH_OP_PLUS,
                2 as i32,
                0 as i32,
                0 as i32,
                0 as *mut libc::c_void,
                0 as *mut libc::c_void,
            );
        } else {
            xmlXPathCompExprAdd(
                ctxt,
                unsafe { (*(*ctxt).comp).last },
                -(1 as i32),
                XPATH_OP_PLUS,
                3 as i32,
                0 as i32,
                0 as i32,
                0 as *mut libc::c_void,
                0 as *mut libc::c_void,
            );
        }
    }
}
extern "C" fn xmlXPathCompMultiplicativeExpr(mut ctxt: xmlXPathParserContextPtr) {
    xmlXPathCompUnaryExpr(ctxt);
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return;
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh268 = unsafe { &mut ((*ctxt).cur) };
            *fresh268 = unsafe { (*fresh268).offset(1) };
        } else {
        };
    }
    while (unsafe { *(*ctxt).cur }) as i32 == '*' as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 'd' as i32
            && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == 'i' as i32
            && (unsafe { *((*ctxt).cur).offset(2 as i32 as isize) }) as i32 == 'v' as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 'm' as i32
            && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == 'o' as i32
            && (unsafe { *((*ctxt).cur).offset(2 as i32 as isize) }) as i32 == 'd' as i32
    {
        let mut op: i32 = -(1 as i32);
        let mut op1: i32 = unsafe { (*(*ctxt).comp).last };
        if (unsafe { *(*ctxt).cur }) as i32 == '*' as i32 {
            op = 0 as i32;
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh269 = unsafe { &mut ((*ctxt).cur) };
                *fresh269 = unsafe { (*fresh269).offset(1) };
            } else {
            };
        } else if (unsafe { *(*ctxt).cur }) as i32 == 'd' as i32 {
            op = 1 as i32;
            let fresh270 = unsafe { &mut ((*ctxt).cur) };
            *fresh270 = unsafe { (*fresh270).offset(3 as i32 as isize) };
        } else if (unsafe { *(*ctxt).cur }) as i32 == 'm' as i32 {
            op = 2 as i32;
            let fresh271 = unsafe { &mut ((*ctxt).cur) };
            *fresh271 = unsafe { (*fresh271).offset(3 as i32 as isize) };
        }
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh272 = unsafe { &mut ((*ctxt).cur) };
                *fresh272 = unsafe { (*fresh272).offset(1) };
            } else {
            };
        }
        xmlXPathCompUnaryExpr(ctxt);
        if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
            return;
        }
        xmlXPathCompExprAdd(
            ctxt,
            op1,
            unsafe { (*(*ctxt).comp).last },
            XPATH_OP_MULT,
            op,
            0 as i32,
            0 as i32,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
        );
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh273 = unsafe { &mut ((*ctxt).cur) };
                *fresh273 = unsafe { (*fresh273).offset(1) };
            } else {
            };
        }
    }
}
extern "C" fn xmlXPathCompAdditiveExpr(mut ctxt: xmlXPathParserContextPtr) {
    xmlXPathCompMultiplicativeExpr(ctxt);
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return;
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh274 = unsafe { &mut ((*ctxt).cur) };
            *fresh274 = unsafe { (*fresh274).offset(1) };
        } else {
        };
    }
    while (unsafe { *(*ctxt).cur }) as i32 == '+' as i32 || (unsafe { *(*ctxt).cur }) as i32 == '-' as i32 {
        let mut plus: i32 = 0;
        let mut op1: i32 = unsafe { (*(*ctxt).comp).last };
        if (unsafe { *(*ctxt).cur }) as i32 == '+' as i32 {
            plus = 1 as i32;
        } else {
            plus = 0 as i32;
        }
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh275 = unsafe { &mut ((*ctxt).cur) };
            *fresh275 = unsafe { (*fresh275).offset(1) };
        } else {
        };
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh276 = unsafe { &mut ((*ctxt).cur) };
                *fresh276 = unsafe { (*fresh276).offset(1) };
            } else {
            };
        }
        xmlXPathCompMultiplicativeExpr(ctxt);
        if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
            return;
        }
        xmlXPathCompExprAdd(
            ctxt,
            op1,
            unsafe { (*(*ctxt).comp).last },
            XPATH_OP_PLUS,
            plus,
            0 as i32,
            0 as i32,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
        );
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh277 = unsafe { &mut ((*ctxt).cur) };
                *fresh277 = unsafe { (*fresh277).offset(1) };
            } else {
            };
        }
    }
}
extern "C" fn xmlXPathCompRelationalExpr(mut ctxt: xmlXPathParserContextPtr) {
    xmlXPathCompAdditiveExpr(ctxt);
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return;
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh278 = unsafe { &mut ((*ctxt).cur) };
            *fresh278 = unsafe { (*fresh278).offset(1) };
        } else {
        };
    }
    while (unsafe { *(*ctxt).cur }) as i32 == '<' as i32 || (unsafe { *(*ctxt).cur }) as i32 == '>' as i32 {
        let mut inf: i32 = 0;
        let mut strict: i32 = 0;
        let mut op1: i32 = unsafe { (*(*ctxt).comp).last };
        if (unsafe { *(*ctxt).cur }) as i32 == '<' as i32 {
            inf = 1 as i32;
        } else {
            inf = 0 as i32;
        }
        if (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == '=' as i32 {
            strict = 0 as i32;
        } else {
            strict = 1 as i32;
        }
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh279 = unsafe { &mut ((*ctxt).cur) };
            *fresh279 = unsafe { (*fresh279).offset(1) };
        } else {
        };
        if strict == 0 {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh280 = unsafe { &mut ((*ctxt).cur) };
                *fresh280 = unsafe { (*fresh280).offset(1) };
            } else {
            };
        }
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh281 = unsafe { &mut ((*ctxt).cur) };
                *fresh281 = unsafe { (*fresh281).offset(1) };
            } else {
            };
        }
        xmlXPathCompAdditiveExpr(ctxt);
        if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
            return;
        }
        xmlXPathCompExprAdd(
            ctxt,
            op1,
            unsafe { (*(*ctxt).comp).last },
            XPATH_OP_CMP,
            inf,
            strict,
            0 as i32,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
        );
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh282 = unsafe { &mut ((*ctxt).cur) };
                *fresh282 = unsafe { (*fresh282).offset(1) };
            } else {
            };
        }
    }
}
extern "C" fn xmlXPathCompEqualityExpr(mut ctxt: xmlXPathParserContextPtr) {
    xmlXPathCompRelationalExpr(ctxt);
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return;
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh283 = unsafe { &mut ((*ctxt).cur) };
            *fresh283 = unsafe { (*fresh283).offset(1) };
        } else {
        };
    }
    while (unsafe { *(*ctxt).cur }) as i32 == '=' as i32
        || (unsafe { *(*ctxt).cur }) as i32 == '!' as i32
            && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == '=' as i32
    {
        let mut eq: i32 = 0;
        let mut op1: i32 = unsafe { (*(*ctxt).comp).last };
        if (unsafe { *(*ctxt).cur }) as i32 == '=' as i32 {
            eq = 1 as i32;
        } else {
            eq = 0 as i32;
        }
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh284 = unsafe { &mut ((*ctxt).cur) };
            *fresh284 = unsafe { (*fresh284).offset(1) };
        } else {
        };
        if eq == 0 {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh285 = unsafe { &mut ((*ctxt).cur) };
                *fresh285 = unsafe { (*fresh285).offset(1) };
            } else {
            };
        }
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh286 = unsafe { &mut ((*ctxt).cur) };
                *fresh286 = unsafe { (*fresh286).offset(1) };
            } else {
            };
        }
        xmlXPathCompRelationalExpr(ctxt);
        if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
            return;
        }
        xmlXPathCompExprAdd(
            ctxt,
            op1,
            unsafe { (*(*ctxt).comp).last },
            XPATH_OP_EQUAL,
            eq,
            0 as i32,
            0 as i32,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
        );
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh287 = unsafe { &mut ((*ctxt).cur) };
                *fresh287 = unsafe { (*fresh287).offset(1) };
            } else {
            };
        }
    }
}
extern "C" fn xmlXPathCompAndExpr(mut ctxt: xmlXPathParserContextPtr) {
    xmlXPathCompEqualityExpr(ctxt);
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return;
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh288 = unsafe { &mut ((*ctxt).cur) };
            *fresh288 = unsafe { (*fresh288).offset(1) };
        } else {
        };
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 'a' as i32
        && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == 'n' as i32
        && (unsafe { *((*ctxt).cur).offset(2 as i32 as isize) }) as i32 == 'd' as i32
    {
        let mut op1: i32 = unsafe { (*(*ctxt).comp).last };
        let fresh289 = unsafe { &mut ((*ctxt).cur) };
        *fresh289 = unsafe { (*fresh289).offset(3 as i32 as isize) };
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh290 = unsafe { &mut ((*ctxt).cur) };
                *fresh290 = unsafe { (*fresh290).offset(1) };
            } else {
            };
        }
        xmlXPathCompEqualityExpr(ctxt);
        if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
            return;
        }
        xmlXPathCompExprAdd(
            ctxt,
            op1,
            unsafe { (*(*ctxt).comp).last },
            XPATH_OP_AND,
            0 as i32,
            0 as i32,
            0 as i32,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
        );
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh291 = unsafe { &mut ((*ctxt).cur) };
                *fresh291 = unsafe { (*fresh291).offset(1) };
            } else {
            };
        }
    }
}
extern "C" fn xmlXPathCompileExpr(mut ctxt: xmlXPathParserContextPtr, mut sort: i32) {
    let mut xpctxt: xmlXPathContextPtr = unsafe { (*ctxt).context };
    if !xpctxt.is_null() {
        if (unsafe { (*xpctxt).depth }) >= 5000 as i32 {
            xmlXPathErr(ctxt, XPATH_RECURSION_LIMIT_EXCEEDED as i32);
            return;
        }
        (unsafe { (*xpctxt).depth += 10 as i32 });
    }
    xmlXPathCompAndExpr(ctxt);
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return;
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh292 = unsafe { &mut ((*ctxt).cur) };
            *fresh292 = unsafe { (*fresh292).offset(1) };
        } else {
        };
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 'o' as i32
        && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == 'r' as i32
    {
        let mut op1: i32 = unsafe { (*(*ctxt).comp).last };
        let fresh293 = unsafe { &mut ((*ctxt).cur) };
        *fresh293 = unsafe { (*fresh293).offset(2 as i32 as isize) };
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh294 = unsafe { &mut ((*ctxt).cur) };
                *fresh294 = unsafe { (*fresh294).offset(1) };
            } else {
            };
        }
        xmlXPathCompAndExpr(ctxt);
        if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
            return;
        }
        xmlXPathCompExprAdd(
            ctxt,
            op1,
            unsafe { (*(*ctxt).comp).last },
            XPATH_OP_OR,
            0 as i32,
            0 as i32,
            0 as i32,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
        );
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh295 = unsafe { &mut ((*ctxt).cur) };
                *fresh295 = unsafe { (*fresh295).offset(1) };
            } else {
            };
        }
    }
    if sort != 0
        && (unsafe { (*((*(*ctxt).comp).steps).offset((*(*ctxt).comp).last as isize)).op }) as u32
            != XPATH_OP_VALUE as i32 as u32
    {
        xmlXPathCompExprAdd(
            ctxt,
            unsafe { (*(*ctxt).comp).last },
            -(1 as i32),
            XPATH_OP_SORT,
            0 as i32,
            0 as i32,
            0 as i32,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
        );
    }
    if !xpctxt.is_null() {
        (unsafe { (*xpctxt).depth -= 10 as i32 });
    }
}
extern "C" fn xmlXPathCompPredicate(mut ctxt: xmlXPathParserContextPtr, mut filter: i32) {
    let mut op1: i32 = unsafe { (*(*ctxt).comp).last };
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh296 = unsafe { &mut ((*ctxt).cur) };
            *fresh296 = unsafe { (*fresh296).offset(1) };
        } else {
        };
    }
    if (unsafe { *(*ctxt).cur }) as i32 != '[' as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_PREDICATE_ERROR as i32);
        return;
    }
    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
        let fresh297 = unsafe { &mut ((*ctxt).cur) };
        *fresh297 = unsafe { (*fresh297).offset(1) };
    } else {
    };
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh298 = unsafe { &mut ((*ctxt).cur) };
            *fresh298 = unsafe { (*fresh298).offset(1) };
        } else {
        };
    }
    (unsafe { (*(*ctxt).comp).last = -(1 as i32) });
    if filter == 0 {
        xmlXPathCompileExpr(ctxt, 0 as i32);
    } else {
        xmlXPathCompileExpr(ctxt, 1 as i32);
    }
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return;
    }
    if (unsafe { *(*ctxt).cur }) as i32 != ']' as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_PREDICATE_ERROR as i32);
        return;
    }
    if filter != 0 {
        xmlXPathCompExprAdd(
            ctxt,
            op1,
            unsafe { (*(*ctxt).comp).last },
            XPATH_OP_FILTER,
            0 as i32,
            0 as i32,
            0 as i32,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
        );
    } else {
        xmlXPathCompExprAdd(
            ctxt,
            op1,
            unsafe { (*(*ctxt).comp).last },
            XPATH_OP_PREDICATE,
            0 as i32,
            0 as i32,
            0 as i32,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
        );
    }
    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
        let fresh299 = unsafe { &mut ((*ctxt).cur) };
        *fresh299 = unsafe { (*fresh299).offset(1) };
    } else {
    };
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh300 = unsafe { &mut ((*ctxt).cur) };
            *fresh300 = unsafe { (*fresh300).offset(1) };
        } else {
        };
    }
}
extern "C" fn xmlXPathCompNodeTest(
    mut ctxt: xmlXPathParserContextPtr,
    mut test: *mut xmlXPathTestVal,
    mut type_0: *mut xmlXPathTypeVal,
    mut prefix: *mut *mut xmlChar,
    mut name: *mut xmlChar,
) -> *mut xmlChar {
    let mut blanks: i32 = 0;
    if test.is_null() || type_0.is_null() || prefix.is_null() {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Internal error at %s:%d\n\0" as *const u8 as *const i8,
            b"xpath.c\0" as *const u8 as *const i8,
            11067 as i32,
        ) });
        return 0 as *mut xmlChar;
    }
    (unsafe { *type_0 = NODE_TYPE_NODE });
    (unsafe { *test = NODE_TEST_NONE });
    (unsafe { *prefix = 0 as *mut xmlChar });
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh301 = unsafe { &mut ((*ctxt).cur) };
            *fresh301 = unsafe { (*fresh301).offset(1) };
        } else {
        };
    }
    if name.is_null() && (unsafe { *(*ctxt).cur }) as i32 == '*' as i32 {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh302 = unsafe { &mut ((*ctxt).cur) };
            *fresh302 = unsafe { (*fresh302).offset(1) };
        } else {
        };
        (unsafe { *test = NODE_TEST_ALL });
        return 0 as *mut xmlChar;
    }
    if name.is_null() {
        name = xmlXPathParseNCName(ctxt);
    }
    if name.is_null() {
        xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
        return 0 as *mut xmlChar;
    }
    blanks = ((unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32) as i32;
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh303 = unsafe { &mut ((*ctxt).cur) };
            *fresh303 = unsafe { (*fresh303).offset(1) };
        } else {
        };
    }
    if (unsafe { *(*ctxt).cur }) as i32 == '(' as i32 {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh304 = unsafe { &mut ((*ctxt).cur) };
            *fresh304 = unsafe { (*fresh304).offset(1) };
        } else {
        };
        if (unsafe { xmlStrEqual(name, b"comment\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
            (unsafe { *type_0 = NODE_TYPE_COMMENT });
        } else if (unsafe { xmlStrEqual(name, b"node\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
            (unsafe { *type_0 = NODE_TYPE_NODE });
        } else if (unsafe { xmlStrEqual(
            name,
            b"processing-instruction\0" as *const u8 as *const i8 as *mut xmlChar,
        ) }) != 0
        {
            (unsafe { *type_0 = NODE_TYPE_PI });
        } else if (unsafe { xmlStrEqual(name, b"text\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
            (unsafe { *type_0 = NODE_TYPE_TEXT });
        } else {
            if !name.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
            }
            xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
            return 0 as *mut xmlChar;
        }
        (unsafe { *test = NODE_TEST_TYPE });
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh305 = unsafe { &mut ((*ctxt).cur) };
                *fresh305 = unsafe { (*fresh305).offset(1) };
            } else {
            };
        }
        if (unsafe { *type_0 }) as u32 == NODE_TYPE_PI as i32 as u32 {
            if !name.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
            }
            name = 0 as *mut xmlChar;
            if (unsafe { *(*ctxt).cur }) as i32 != ')' as i32 {
                name = xmlXPathParseLiteral(ctxt);
                if name.is_null() {
                    xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
                    return 0 as *mut xmlChar;
                }
                (unsafe { *test = NODE_TEST_PI });
                while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                    || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                {
                    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                        let fresh306 = unsafe { &mut ((*ctxt).cur) };
                        *fresh306 = unsafe { (*fresh306).offset(1) };
                    } else {
                    };
                }
            }
        }
        if (unsafe { *(*ctxt).cur }) as i32 != ')' as i32 {
            if !name.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
            }
            xmlXPathErr(ctxt, XPATH_UNCLOSED_ERROR as i32);
            return 0 as *mut xmlChar;
        }
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh307 = unsafe { &mut ((*ctxt).cur) };
            *fresh307 = unsafe { (*fresh307).offset(1) };
        } else {
        };
        return name;
    }
    (unsafe { *test = NODE_TEST_NAME });
    if blanks == 0 && (unsafe { *(*ctxt).cur }) as i32 == ':' as i32 {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh308 = unsafe { &mut ((*ctxt).cur) };
            *fresh308 = unsafe { (*fresh308).offset(1) };
        } else {
        };
        (unsafe { *prefix = name });
        if (unsafe { *(*ctxt).cur }) as i32 == '*' as i32 {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh309 = unsafe { &mut ((*ctxt).cur) };
                *fresh309 = unsafe { (*fresh309).offset(1) };
            } else {
            };
            (unsafe { *test = NODE_TEST_ALL });
            return 0 as *mut xmlChar;
        }
        name = xmlXPathParseNCName(ctxt);
        if name.is_null() {
            xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
            return 0 as *mut xmlChar;
        }
    }
    return name;
}
extern "C" fn xmlXPathIsAxisName(mut name: *const xmlChar) -> xmlXPathAxisVal {
    let mut ret: xmlXPathAxisVal = 0 as xmlXPathAxisVal;
    match (unsafe { *name.offset(0 as i32 as isize) }) as i32 {
        97 => {
            if (unsafe { xmlStrEqual(
                name,
                b"ancestor\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) != 0
            {
                ret = AXIS_ANCESTOR;
            }
            if (unsafe { xmlStrEqual(
                name,
                b"ancestor-or-self\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) != 0
            {
                ret = AXIS_ANCESTOR_OR_SELF;
            }
            if (unsafe { xmlStrEqual(
                name,
                b"attribute\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) != 0
            {
                ret = AXIS_ATTRIBUTE;
            }
        }
        99 => {
            if (unsafe { xmlStrEqual(name, b"child\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
                ret = AXIS_CHILD;
            }
        }
        100 => {
            if (unsafe { xmlStrEqual(
                name,
                b"descendant\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) != 0
            {
                ret = AXIS_DESCENDANT;
            }
            if (unsafe { xmlStrEqual(
                name,
                b"descendant-or-self\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) != 0
            {
                ret = AXIS_DESCENDANT_OR_SELF;
            }
        }
        102 => {
            if (unsafe { xmlStrEqual(
                name,
                b"following\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) != 0
            {
                ret = AXIS_FOLLOWING;
            }
            if (unsafe { xmlStrEqual(
                name,
                b"following-sibling\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) != 0
            {
                ret = AXIS_FOLLOWING_SIBLING;
            }
        }
        110 => {
            if (unsafe { xmlStrEqual(
                name,
                b"namespace\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) != 0
            {
                ret = AXIS_NAMESPACE;
            }
        }
        112 => {
            if (unsafe { xmlStrEqual(name, b"parent\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
                ret = AXIS_PARENT;
            }
            if (unsafe { xmlStrEqual(
                name,
                b"preceding\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) != 0
            {
                ret = AXIS_PRECEDING;
            }
            if (unsafe { xmlStrEqual(
                name,
                b"preceding-sibling\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) != 0
            {
                ret = AXIS_PRECEDING_SIBLING;
            }
        }
        115 => {
            if (unsafe { xmlStrEqual(name, b"self\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
                ret = AXIS_SELF;
            }
        }
        _ => {}
    }
    return ret;
}
extern "C" fn xmlXPathCompStep(mut ctxt: xmlXPathParserContextPtr) {
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh310 = unsafe { &mut ((*ctxt).cur) };
            *fresh310 = unsafe { (*fresh310).offset(1) };
        } else {
        };
    }
    if (unsafe { *(*ctxt).cur }) as i32 == '.' as i32
        && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == '.' as i32
    {
        let fresh311 = unsafe { &mut ((*ctxt).cur) };
        *fresh311 = unsafe { (*fresh311).offset(2 as i32 as isize) };
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh312 = unsafe { &mut ((*ctxt).cur) };
                *fresh312 = unsafe { (*fresh312).offset(1) };
            } else {
            };
        }
        xmlXPathCompExprAdd(
            ctxt,
            unsafe { (*(*ctxt).comp).last },
            -(1 as i32),
            XPATH_OP_COLLECT,
            AXIS_PARENT as i32,
            NODE_TEST_TYPE as i32,
            NODE_TYPE_NODE as i32,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
        );
    } else if (unsafe { *(*ctxt).cur }) as i32 == '.' as i32 {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh313 = unsafe { &mut ((*ctxt).cur) };
            *fresh313 = unsafe { (*fresh313).offset(1) };
        } else {
        };
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh314 = unsafe { &mut ((*ctxt).cur) };
                *fresh314 = unsafe { (*fresh314).offset(1) };
            } else {
            };
        }
    } else {
        let mut name: *mut xmlChar = 0 as *mut xmlChar;
        let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
        let mut test: xmlXPathTestVal = NODE_TEST_NONE;
        let mut axis: xmlXPathAxisVal = 0 as xmlXPathAxisVal;
        let mut type_0: xmlXPathTypeVal = NODE_TYPE_NODE;
        let mut op1: i32 = 0;
        if (unsafe { *(*ctxt).cur }) as i32 == '*' as i32 {
            axis = AXIS_CHILD;
        } else {
            if name.is_null() {
                name = xmlXPathParseNCName(ctxt);
            }
            if !name.is_null() {
                axis = xmlXPathIsAxisName(name);
                if axis as u32 != 0 as i32 as u32 {
                    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                    {
                        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                            let fresh315 = unsafe { &mut ((*ctxt).cur) };
                            *fresh315 = unsafe { (*fresh315).offset(1) };
                        } else {
                        };
                    }
                    if (unsafe { *(*ctxt).cur }) as i32 == ':' as i32
                        && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == ':' as i32
                    {
                        let fresh316 = unsafe { &mut ((*ctxt).cur) };
                        *fresh316 = unsafe { (*fresh316).offset(2 as i32 as isize) };
                        (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
                        name = 0 as *mut xmlChar;
                    } else {
                        axis = AXIS_CHILD;
                    }
                } else {
                    axis = AXIS_CHILD;
                }
            } else if (unsafe { *(*ctxt).cur }) as i32 == '@' as i32 {
                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                    let fresh317 = unsafe { &mut ((*ctxt).cur) };
                    *fresh317 = unsafe { (*fresh317).offset(1) };
                } else {
                };
                axis = AXIS_ATTRIBUTE;
            } else {
                axis = AXIS_CHILD;
            }
        }
        if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
            (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
            return;
        }
        name = xmlXPathCompNodeTest(ctxt, &mut test, &mut type_0, &mut prefix, name);
        if test as u32 == 0 as i32 as u32 {
            return;
        }
        if !prefix.is_null()
            && !(unsafe { (*ctxt).context }).is_null()
            && (unsafe { (*(*ctxt).context).flags }) & (1 as i32) << 0 as i32 != 0
        {
            if (xmlXPathNsLookup(unsafe { (*ctxt).context }, prefix)).is_null() {
                xmlXPathErr(ctxt, XPATH_UNDEF_PREFIX_ERROR as i32);
            }
        }
        op1 = unsafe { (*(*ctxt).comp).last };
        (unsafe { (*(*ctxt).comp).last = -(1 as i32) });
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh318 = unsafe { &mut ((*ctxt).cur) };
                *fresh318 = unsafe { (*fresh318).offset(1) };
            } else {
            };
        }
        while (unsafe { *(*ctxt).cur }) as i32 == '[' as i32 {
            xmlXPathCompPredicate(ctxt, 0 as i32);
        }
        if xmlXPathCompExprAdd(
            ctxt,
            op1,
            unsafe { (*(*ctxt).comp).last },
            XPATH_OP_COLLECT,
            axis as i32,
            test as i32,
            type_0 as i32,
            prefix as *mut libc::c_void,
            name as *mut libc::c_void,
        ) == -(1 as i32)
        {
            (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
            (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
        }
    };
}
extern "C" fn xmlXPathCompRelativeLocationPath(mut ctxt: xmlXPathParserContextPtr) {
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh319 = unsafe { &mut ((*ctxt).cur) };
            *fresh319 = unsafe { (*fresh319).offset(1) };
        } else {
        };
    }
    if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32
        && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32
    {
        let fresh320 = unsafe { &mut ((*ctxt).cur) };
        *fresh320 = unsafe { (*fresh320).offset(2 as i32 as isize) };
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh321 = unsafe { &mut ((*ctxt).cur) };
                *fresh321 = unsafe { (*fresh321).offset(1) };
            } else {
            };
        }
        xmlXPathCompExprAdd(
            ctxt,
            unsafe { (*(*ctxt).comp).last },
            -(1 as i32),
            XPATH_OP_COLLECT,
            AXIS_DESCENDANT_OR_SELF as i32,
            NODE_TEST_TYPE as i32,
            NODE_TYPE_NODE as i32,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
        );
    } else if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32 {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh322 = unsafe { &mut ((*ctxt).cur) };
            *fresh322 = unsafe { (*fresh322).offset(1) };
        } else {
        };
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh323 = unsafe { &mut ((*ctxt).cur) };
                *fresh323 = unsafe { (*fresh323).offset(1) };
            } else {
            };
        }
    }
    xmlXPathCompStep(ctxt);
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return;
    }
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh324 = unsafe { &mut ((*ctxt).cur) };
            *fresh324 = unsafe { (*fresh324).offset(1) };
        } else {
        };
    }
    while (unsafe { *(*ctxt).cur }) as i32 == '/' as i32 {
        if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32
            && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32
        {
            let fresh325 = unsafe { &mut ((*ctxt).cur) };
            *fresh325 = unsafe { (*fresh325).offset(2 as i32 as isize) };
            while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            {
                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                    let fresh326 = unsafe { &mut ((*ctxt).cur) };
                    *fresh326 = unsafe { (*fresh326).offset(1) };
                } else {
                };
            }
            xmlXPathCompExprAdd(
                ctxt,
                unsafe { (*(*ctxt).comp).last },
                -(1 as i32),
                XPATH_OP_COLLECT,
                AXIS_DESCENDANT_OR_SELF as i32,
                NODE_TEST_TYPE as i32,
                NODE_TYPE_NODE as i32,
                0 as *mut libc::c_void,
                0 as *mut libc::c_void,
            );
            xmlXPathCompStep(ctxt);
        } else if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32 {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh327 = unsafe { &mut ((*ctxt).cur) };
                *fresh327 = unsafe { (*fresh327).offset(1) };
            } else {
            };
            while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            {
                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                    let fresh328 = unsafe { &mut ((*ctxt).cur) };
                    *fresh328 = unsafe { (*fresh328).offset(1) };
                } else {
                };
            }
            xmlXPathCompStep(ctxt);
        }
        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
        {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh329 = unsafe { &mut ((*ctxt).cur) };
                *fresh329 = unsafe { (*fresh329).offset(1) };
            } else {
            };
        }
    }
}
extern "C" fn xmlXPathCompLocationPath(mut ctxt: xmlXPathParserContextPtr) {
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh330 = unsafe { &mut ((*ctxt).cur) };
            *fresh330 = unsafe { (*fresh330).offset(1) };
        } else {
        };
    }
    if (unsafe { *(*ctxt).cur }) as i32 != '/' as i32 {
        xmlXPathCompRelativeLocationPath(ctxt);
    } else {
        while (unsafe { *(*ctxt).cur }) as i32 == '/' as i32 {
            if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32
                && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32
            {
                let fresh331 = unsafe { &mut ((*ctxt).cur) };
                *fresh331 = unsafe { (*fresh331).offset(2 as i32 as isize) };
                while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                    || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                {
                    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                        let fresh332 = unsafe { &mut ((*ctxt).cur) };
                        *fresh332 = unsafe { (*fresh332).offset(1) };
                    } else {
                    };
                }
                xmlXPathCompExprAdd(
                    ctxt,
                    unsafe { (*(*ctxt).comp).last },
                    -(1 as i32),
                    XPATH_OP_COLLECT,
                    AXIS_DESCENDANT_OR_SELF as i32,
                    NODE_TEST_TYPE as i32,
                    NODE_TYPE_NODE as i32,
                    0 as *mut libc::c_void,
                    0 as *mut libc::c_void,
                );
                xmlXPathCompRelativeLocationPath(ctxt);
            } else if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32 {
                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                    let fresh333 = unsafe { &mut ((*ctxt).cur) };
                    *fresh333 = unsafe { (*fresh333).offset(1) };
                } else {
                };
                while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                    || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                {
                    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                        let fresh334 = unsafe { &mut ((*ctxt).cur) };
                        *fresh334 = unsafe { (*fresh334).offset(1) };
                    } else {
                    };
                }
                if (unsafe { *(*ctxt).cur }) as i32 != 0 as i32
                    && (0x41 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0x5a as i32
                        || 0x61 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0x7a as i32
                        || (unsafe { *(*ctxt).cur }) as i32 == '_' as i32
                        || (unsafe { *(*ctxt).cur }) as i32 == '.' as i32
                        || (unsafe { *(*ctxt).cur }) as i32 == '@' as i32
                        || (unsafe { *(*ctxt).cur }) as i32 == '*' as i32)
                {
                    xmlXPathCompRelativeLocationPath(ctxt);
                }
            }
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return;
            }
        }
    };
}
extern "C" fn xmlXPathNodeSetFilter(
    mut ctxt: xmlXPathParserContextPtr,
    mut set: xmlNodeSetPtr,
    mut filterOpIndex: i32,
    mut minPos: i32,
    mut maxPos: i32,
    mut hasNsNodes: i32,
) {
    let mut xpctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut oldnode: xmlNodePtr = 0 as *mut xmlNode;
    let mut olddoc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut filterOp: xmlXPathStepOpPtr = 0 as *mut xmlXPathStepOp;
    let mut oldcs: i32 = 0;
    let mut oldpp: i32 = 0;
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    let mut pos: i32 = 0;
    if set.is_null() || (unsafe { (*set).nodeNr }) == 0 as i32 {
        return;
    }
    if (unsafe { (*set).nodeNr }) < minPos {
        xmlXPathNodeSetClear(set, hasNsNodes);
        return;
    }
    xpctxt = unsafe { (*ctxt).context };
    oldnode = unsafe { (*xpctxt).node };
    olddoc = unsafe { (*xpctxt).doc };
    oldcs = unsafe { (*xpctxt).contextSize };
    oldpp = unsafe { (*xpctxt).proximityPosition };
    filterOp = (unsafe { &mut *((*(*ctxt).comp).steps).offset(filterOpIndex as isize) }) as *mut xmlXPathStepOp;
    (unsafe { (*xpctxt).contextSize = (*set).nodeNr });
    i = 0 as i32;
    j = 0 as i32;
    pos = 1 as i32;
    while i < (unsafe { (*set).nodeNr }) {
        let mut node: xmlNodePtr = unsafe { *((*set).nodeTab).offset(i as isize) };
        let mut res: i32 = 0;
        let fresh335 = unsafe { &mut ((*xpctxt).node) };
        *fresh335 = node;
        (unsafe { (*xpctxt).proximityPosition = i + 1 as i32 });
        if (unsafe { (*node).type_0 }) as u32 != XML_NAMESPACE_DECL as i32 as u32 && !(unsafe { (*node).doc }).is_null() {
            let fresh336 = unsafe { &mut ((*xpctxt).doc) };
            *fresh336 = unsafe { (*node).doc };
        }
        res = xmlXPathCompOpEvalToBoolean(ctxt, filterOp, 1 as i32);
        if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
            break;
        }
        if res < 0 as i32 {
            xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
            break;
        } else {
            if res != 0 as i32 && (pos >= minPos && pos <= maxPos) {
                if i != j {
                    let fresh337 = unsafe { &mut (*((*set).nodeTab).offset(j as isize)) };
                    *fresh337 = node;
                    let fresh338 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                    *fresh338 = 0 as xmlNodePtr;
                }
                j += 1 as i32;
            } else {
                let fresh339 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                *fresh339 = 0 as xmlNodePtr;
                if (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
                    xmlXPathNodeSetFreeNs(node as xmlNsPtr);
                }
            }
            if res != 0 as i32 {
                if pos == maxPos {
                    i += 1 as i32;
                    break;
                } else {
                    pos += 1 as i32;
                }
            }
            i += 1;
        }
    }
    if hasNsNodes != 0 {
        while i < (unsafe { (*set).nodeNr }) {
            let mut node_0: xmlNodePtr = unsafe { *((*set).nodeTab).offset(i as isize) };
            if !node_0.is_null() && (unsafe { (*node_0).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
                xmlXPathNodeSetFreeNs(node_0 as xmlNsPtr);
            }
            i += 1;
        }
    }
    (unsafe { (*set).nodeNr = j });
    if (unsafe { (*set).nodeMax }) > 10 as i32 && (unsafe { (*set).nodeNr }) < (unsafe { (*set).nodeMax }) / 2 as i32 {
        let mut tmp: *mut xmlNodePtr = 0 as *mut xmlNodePtr;
        let mut nodeMax: i32 = unsafe { (*set).nodeNr };
        if nodeMax < 10 as i32 {
            nodeMax = 10 as i32;
        }
        tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*set).nodeTab as *mut libc::c_void,
            (nodeMax as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) }) as *mut xmlNodePtr;
        if tmp.is_null() {
            xmlXPathPErrMemory(ctxt, b"shrinking nodeset\n\0" as *const u8 as *const i8);
        } else {
            let fresh340 = unsafe { &mut ((*set).nodeTab) };
            *fresh340 = tmp;
            (unsafe { (*set).nodeMax = nodeMax });
        }
    }
    let fresh341 = unsafe { &mut ((*xpctxt).node) };
    *fresh341 = oldnode;
    let fresh342 = unsafe { &mut ((*xpctxt).doc) };
    *fresh342 = olddoc;
    (unsafe { (*xpctxt).contextSize = oldcs });
    (unsafe { (*xpctxt).proximityPosition = oldpp });
}
extern "C" fn xmlXPathCompOpEvalPredicate(
    mut ctxt: xmlXPathParserContextPtr,
    mut op: xmlXPathStepOpPtr,
    mut set: xmlNodeSetPtr,
    mut minPos: i32,
    mut maxPos: i32,
    mut hasNsNodes: i32,
) {
    if (unsafe { (*op).ch1 }) != -(1 as i32) {
        let mut comp: xmlXPathCompExprPtr = unsafe { (*ctxt).comp };
        if (unsafe { (*((*comp).steps).offset((*op).ch1 as isize)).op }) as u32
            != XPATH_OP_PREDICATE as i32 as u32
        {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlXPathCompOpEvalPredicate: Expected a predicate\n\0" as *const u8 as *const i8,
            ) });
            xmlXPathErr(ctxt, XPATH_INVALID_OPERAND as i32);
            return;
        }
        if (unsafe { (*(*ctxt).context).depth }) >= 5000 as i32 {
            xmlXPathErr(ctxt, XPATH_RECURSION_LIMIT_EXCEEDED as i32);
            return;
        }
        (unsafe { (*(*ctxt).context).depth += 1 as i32 });
        xmlXPathCompOpEvalPredicate(
            ctxt,
            unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) },
            set,
            1 as i32,
            unsafe { (*set).nodeNr },
            hasNsNodes,
        );
        (unsafe { (*(*ctxt).context).depth -= 1 as i32 });
        if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
            return;
        }
    }
    if (unsafe { (*op).ch2 }) != -(1 as i32) {
        xmlXPathNodeSetFilter(ctxt, set, unsafe { (*op).ch2 }, minPos, maxPos, hasNsNodes);
    }
}
extern "C" fn xmlXPathIsPositionalPredicate(
    mut ctxt: xmlXPathParserContextPtr,
    mut op: xmlXPathStepOpPtr,
    mut maxPos: *mut i32,
) -> i32 {
    let mut exprOp: xmlXPathStepOpPtr = 0 as *mut xmlXPathStepOp;
    if (unsafe { (*op).op }) as u32 != XPATH_OP_PREDICATE as i32 as u32
        && (unsafe { (*op).op }) as u32 != XPATH_OP_FILTER as i32 as u32
    {
        return 0 as i32;
    }
    if (unsafe { (*op).ch2 }) != -(1 as i32) {
        exprOp = (unsafe { &mut *((*(*ctxt).comp).steps).offset((*op).ch2 as isize) }) as *mut xmlXPathStepOp;
    } else {
        return 0 as i32;
    }
    if !exprOp.is_null()
        && (unsafe { (*exprOp).op }) as u32 == XPATH_OP_VALUE as i32 as u32
        && !(unsafe { (*exprOp).value4 }).is_null()
        && (unsafe { (*((*exprOp).value4 as xmlXPathObjectPtr)).type_0 }) as u32 == XPATH_NUMBER as i32 as u32
    {
        let mut floatval: f64 = unsafe { (*((*exprOp).value4 as xmlXPathObjectPtr)).floatval };
        if floatval > (-(2147483647 as i32) - 1 as i32) as f64
            && floatval < 2147483647 as i32 as f64
        {
            (unsafe { *maxPos = floatval as i32 });
            if floatval == (unsafe { *maxPos }) as f64 {
                return 1 as i32;
            }
        }
    }
    return 0 as i32;
}
extern "C" fn xmlXPathNodeCollectAndTest(
    mut ctxt: xmlXPathParserContextPtr,
    mut op: xmlXPathStepOpPtr,
    mut first: *mut xmlNodePtr,
    mut last: *mut xmlNodePtr,
    mut toBool: i32,
) -> i32 {
    let mut current_block: u64;
    let mut axis: xmlXPathAxisVal = (unsafe { (*op).value }) as xmlXPathAxisVal;
    let mut test: xmlXPathTestVal = (unsafe { (*op).value2 }) as xmlXPathTestVal;
    let mut type_0: xmlXPathTypeVal = (unsafe { (*op).value3 }) as xmlXPathTypeVal;
    let mut prefix: *const xmlChar = (unsafe { (*op).value4 }) as *const xmlChar;
    let mut name: *const xmlChar = (unsafe { (*op).value5 }) as *const xmlChar;
    let mut URI: *const xmlChar = 0 as *const xmlChar;
    let mut total: i32 = 0 as i32;
    let mut hasNsNodes: i32 = 0 as i32;
    let mut obj: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut contextSeq: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut contextIdx: i32 = 0;
    let mut contextNode: xmlNodePtr = 0 as *mut xmlNode;
    let mut outSeq: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut seq: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut predOp: xmlXPathStepOpPtr = 0 as *mut xmlXPathStepOp;
    let mut maxPos: i32 = 0;
    let mut hasPredicateRange: i32 = 0;
    let mut hasAxisRange: i32 = 0;
    let mut pos: i32 = 0;
    let mut breakOnFirstHit: i32 = 0;
    let mut next: xmlXPathTraversalFunction = None;
    let mut addNode: Option<unsafe extern "C" fn(xmlNodeSetPtr, xmlNodePtr) -> i32> = None;
    let mut mergeAndClear: xmlXPathNodeSetMergeFunction = None;
    let mut oldContextNode: xmlNodePtr = 0 as *mut xmlNode;
    let mut xpctxt: xmlXPathContextPtr = unsafe { (*ctxt).context };
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NODESET as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return 0 as i32;
    }
    obj = valuePop(ctxt);
    if !prefix.is_null() {
        URI = xmlXPathNsLookup(xpctxt, prefix);
        if URI.is_null() {
            xmlXPathReleaseObject(xpctxt, obj);
            xmlXPathErr(ctxt, XPATH_UNDEF_PREFIX_ERROR as i32);
            return 0 as i32;
        }
    }
    mergeAndClear = Some(
        xmlXPathNodeSetMergeAndClear
            as unsafe extern "C" fn(xmlNodeSetPtr, xmlNodeSetPtr) -> xmlNodeSetPtr,
    );
    match axis as u32 {
        1 => {
            first = 0 as *mut xmlNodePtr;
            next = Some(
                xmlXPathNextAncestor
                    as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
            );
        }
        2 => {
            first = 0 as *mut xmlNodePtr;
            next = Some(
                xmlXPathNextAncestorOrSelf
                    as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
            );
        }
        3 => {
            first = 0 as *mut xmlNodePtr;
            last = 0 as *mut xmlNodePtr;
            next = Some(
                xmlXPathNextAttribute
                    as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
            );
            mergeAndClear = Some(
                xmlXPathNodeSetMergeAndClearNoDupls
                    as unsafe extern "C" fn(xmlNodeSetPtr, xmlNodeSetPtr) -> xmlNodeSetPtr,
            );
        }
        4 => {
            last = 0 as *mut xmlNodePtr;
            if (test as u32 == NODE_TEST_NAME as i32 as u32
                || test as u32 == NODE_TEST_ALL as i32 as u32)
                && type_0 as u32 == NODE_TYPE_NODE as i32 as u32
            {
                next = Some(
                    xmlXPathNextChildElement
                        as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
                );
            } else {
                next = Some(
                    xmlXPathNextChild
                        as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
                );
            }
            mergeAndClear = Some(
                xmlXPathNodeSetMergeAndClearNoDupls
                    as unsafe extern "C" fn(xmlNodeSetPtr, xmlNodeSetPtr) -> xmlNodeSetPtr,
            );
        }
        5 => {
            last = 0 as *mut xmlNodePtr;
            next = Some(
                xmlXPathNextDescendant
                    as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
            );
        }
        6 => {
            last = 0 as *mut xmlNodePtr;
            next = Some(
                xmlXPathNextDescendantOrSelf
                    as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
            );
        }
        7 => {
            last = 0 as *mut xmlNodePtr;
            next = Some(
                xmlXPathNextFollowing
                    as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
            );
        }
        8 => {
            last = 0 as *mut xmlNodePtr;
            next = Some(
                xmlXPathNextFollowingSibling
                    as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
            );
        }
        9 => {
            first = 0 as *mut xmlNodePtr;
            last = 0 as *mut xmlNodePtr;
            next = unsafe { ::std::mem::transmute::<
                Option<unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr>,
                xmlXPathTraversalFunction,
            >(Some(
                xmlXPathNextNamespace
                    as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
            )) };
            mergeAndClear = Some(
                xmlXPathNodeSetMergeAndClearNoDupls
                    as unsafe extern "C" fn(xmlNodeSetPtr, xmlNodeSetPtr) -> xmlNodeSetPtr,
            );
        }
        10 => {
            first = 0 as *mut xmlNodePtr;
            next = Some(
                xmlXPathNextParent
                    as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
            );
        }
        11 => {
            first = 0 as *mut xmlNodePtr;
            next = Some(
                xmlXPathNextPrecedingInternal
                    as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
            );
        }
        12 => {
            first = 0 as *mut xmlNodePtr;
            next = Some(
                xmlXPathNextPrecedingSibling
                    as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
            );
        }
        13 => {
            first = 0 as *mut xmlNodePtr;
            last = 0 as *mut xmlNodePtr;
            next = Some(
                xmlXPathNextSelf
                    as unsafe extern "C" fn(xmlXPathParserContextPtr, xmlNodePtr) -> xmlNodePtr,
            );
            mergeAndClear = Some(
                xmlXPathNodeSetMergeAndClearNoDupls
                    as unsafe extern "C" fn(xmlNodeSetPtr, xmlNodeSetPtr) -> xmlNodeSetPtr,
            );
        }
        _ => {}
    }
    if next.is_none() {
        xmlXPathReleaseObject(xpctxt, obj);
        return 0 as i32;
    }
    contextSeq = unsafe { (*obj).nodesetval };
    if contextSeq.is_null() || (unsafe { (*contextSeq).nodeNr }) <= 0 as i32 {
        xmlXPathReleaseObject(xpctxt, obj);
        valuePush(ctxt, xmlXPathCacheWrapNodeSet(xpctxt, 0 as xmlNodeSetPtr));
        return 0 as i32;
    }
    maxPos = 0 as i32;
    predOp = 0 as xmlXPathStepOpPtr;
    hasPredicateRange = 0 as i32;
    hasAxisRange = 0 as i32;
    if (unsafe { (*op).ch2 }) != -(1 as i32) {
        predOp = (unsafe { &mut *((*(*ctxt).comp).steps).offset((*op).ch2 as isize) }) as *mut xmlXPathStepOp;
        if xmlXPathIsPositionalPredicate(ctxt, predOp, &mut maxPos) != 0 {
            if (unsafe { (*predOp).ch1 }) != -(1 as i32) {
                predOp = (unsafe { &mut *((*(*ctxt).comp).steps).offset((*predOp).ch1 as isize) })
                    as *mut xmlXPathStepOp;
                hasPredicateRange = 1 as i32;
            } else {
                predOp = 0 as xmlXPathStepOpPtr;
                hasAxisRange = 1 as i32;
            }
        }
    }
    breakOnFirstHit = if toBool != 0 && predOp.is_null() {
        1 as i32
    } else {
        0 as i32
    };
    oldContextNode = unsafe { (*xpctxt).node };
    addNode =
        Some(xmlXPathNodeSetAddUnique as unsafe extern "C" fn(xmlNodeSetPtr, xmlNodePtr) -> i32);
    outSeq = 0 as xmlNodeSetPtr;
    seq = 0 as xmlNodeSetPtr;
    contextNode = 0 as xmlNodePtr;
    contextIdx = 0 as i32;
    's_486: while (contextIdx < (unsafe { (*contextSeq).nodeNr }) || !contextNode.is_null())
        && (unsafe { (*ctxt).error }) == XPATH_EXPRESSION_OK as i32
    {
        let fresh343 = contextIdx;
        contextIdx = contextIdx + 1;
        let fresh344 = unsafe { &mut ((*xpctxt).node) };
        *fresh344 = unsafe { *((*contextSeq).nodeTab).offset(fresh343 as isize) };
        if seq.is_null() {
            seq = xmlXPathNodeSetCreate(0 as xmlNodePtr);
            if seq.is_null() {
                total = 0 as i32;
                break;
            }
        }
        pos = 0 as i32;
        cur = 0 as xmlNodePtr;
        hasNsNodes = 0 as i32;
        loop {
            if (unsafe { (*(*ctxt).context).opLimit }) != 0 as i32 as u64
                && xmlXPathCheckOpLimit(ctxt, 1 as i32 as u64) < 0 as i32
            {
                break 's_486;
            }
            cur = unsafe { next.expect("non-null function pointer")(ctxt, cur) };
            if cur.is_null() {
                current_block = 16313108704606884446;
                break;
            }
            if !first.is_null() && !(unsafe { *first }).is_null() {
                if (unsafe { *first }) == cur {
                    current_block = 16313108704606884446;
                    break;
                }
                if total % 256 as i32 == 0 as i32 && xmlXPathCmpNodesExt(unsafe { *first }, cur) >= 0 as i32 {
                    current_block = 16313108704606884446;
                    break;
                }
            }
            if !last.is_null() && !(unsafe { *last }).is_null() {
                if (unsafe { *last }) == cur {
                    current_block = 16313108704606884446;
                    break;
                }
                if total % 256 as i32 == 0 as i32 && xmlXPathCmpNodesExt(cur, unsafe { *last }) >= 0 as i32 {
                    current_block = 16313108704606884446;
                    break;
                }
            }
            total += 1;
            match test as u32 {
                0 => {
                    total = 0 as i32;
                    (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"Internal error at %s:%d\n\0" as *const u8 as *const i8,
                        b"xpath.c\0" as *const u8 as *const i8,
                        12271 as i32,
                    ) });
                    break 's_486;
                }
                1 => {
                    if type_0 as u32 == NODE_TYPE_NODE as i32 as u32 {
                        match (unsafe { (*cur).type_0 }) as u32 {
                            9 | 13 | 1 | 2 | 7 | 8 | 4 | 3 => {
                                current_block = 16751756738514599728;
                                match current_block {
                                    16751756738514599728 => {
                                        if hasAxisRange != 0 as i32 {
                                            pos += 1;
                                            if pos == maxPos {
                                                if (unsafe { addNode.expect("non-null function pointer")(
                                                    seq, cur,
                                                ) }) < 0 as i32
                                                {
                                                    (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                }
                                                current_block = 16871635383312547059;
                                                break;
                                            }
                                        } else {
                                            if (unsafe { addNode.expect("non-null function pointer")(seq, cur) })
                                                < 0 as i32
                                            {
                                                (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                            }
                                            if breakOnFirstHit != 0 {
                                                current_block = 6058993197908835384;
                                                break;
                                            }
                                        }
                                    }
                                    _ => {
                                        if axis as u32 == AXIS_NAMESPACE as i32 as u32 {
                                            if hasAxisRange != 0 as i32 {
                                                pos += 1;
                                                if pos == maxPos {
                                                    hasNsNodes = 1 as i32;
                                                    if xmlXPathNodeSetAddNs(
                                                        seq,
                                                        unsafe { (*xpctxt).node },
                                                        cur as xmlNsPtr,
                                                    ) < 0 as i32
                                                    {
                                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                    }
                                                    current_block = 16871635383312547059;
                                                    break;
                                                }
                                            } else {
                                                hasNsNodes = 1 as i32;
                                                if xmlXPathNodeSetAddNs(
                                                    seq,
                                                    unsafe { (*xpctxt).node },
                                                    cur as xmlNsPtr,
                                                ) < 0 as i32
                                                {
                                                    (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                }
                                                if breakOnFirstHit != 0 {
                                                    current_block = 6058993197908835384;
                                                    break;
                                                }
                                            }
                                        } else {
                                            hasNsNodes = 1 as i32;
                                            if hasAxisRange != 0 as i32 {
                                                pos += 1;
                                                if pos == maxPos {
                                                    if (unsafe { addNode.expect("non-null function pointer")(
                                                        seq, cur,
                                                    ) }) < 0 as i32
                                                    {
                                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                    }
                                                    current_block = 16871635383312547059;
                                                    break;
                                                }
                                            } else {
                                                if (unsafe { addNode.expect("non-null function pointer")(
                                                    seq, cur,
                                                ) }) < 0 as i32
                                                {
                                                    (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                }
                                                if breakOnFirstHit != 0 {
                                                    current_block = 6058993197908835384;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            18 => {
                                current_block = 5431927413890720344;
                                match current_block {
                                    16751756738514599728 => {
                                        if hasAxisRange != 0 as i32 {
                                            pos += 1;
                                            if pos == maxPos {
                                                if (unsafe { addNode.expect("non-null function pointer")(
                                                    seq, cur,
                                                ) }) < 0 as i32
                                                {
                                                    (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                }
                                                current_block = 16871635383312547059;
                                                break;
                                            }
                                        } else {
                                            if (unsafe { addNode.expect("non-null function pointer")(seq, cur) })
                                                < 0 as i32
                                            {
                                                (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                            }
                                            if breakOnFirstHit != 0 {
                                                current_block = 6058993197908835384;
                                                break;
                                            }
                                        }
                                    }
                                    _ => {
                                        if axis as u32 == AXIS_NAMESPACE as i32 as u32 {
                                            if hasAxisRange != 0 as i32 {
                                                pos += 1;
                                                if pos == maxPos {
                                                    hasNsNodes = 1 as i32;
                                                    if xmlXPathNodeSetAddNs(
                                                        seq,
                                                        unsafe { (*xpctxt).node },
                                                        cur as xmlNsPtr,
                                                    ) < 0 as i32
                                                    {
                                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                    }
                                                    current_block = 16871635383312547059;
                                                    break;
                                                }
                                            } else {
                                                hasNsNodes = 1 as i32;
                                                if xmlXPathNodeSetAddNs(
                                                    seq,
                                                    unsafe { (*xpctxt).node },
                                                    cur as xmlNsPtr,
                                                ) < 0 as i32
                                                {
                                                    (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                }
                                                if breakOnFirstHit != 0 {
                                                    current_block = 6058993197908835384;
                                                    break;
                                                }
                                            }
                                        } else {
                                            hasNsNodes = 1 as i32;
                                            if hasAxisRange != 0 as i32 {
                                                pos += 1;
                                                if pos == maxPos {
                                                    if (unsafe { addNode.expect("non-null function pointer")(
                                                        seq, cur,
                                                    ) }) < 0 as i32
                                                    {
                                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                    }
                                                    current_block = 16871635383312547059;
                                                    break;
                                                }
                                            } else {
                                                if (unsafe { addNode.expect("non-null function pointer")(
                                                    seq, cur,
                                                ) }) < 0 as i32
                                                {
                                                    (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                }
                                                if breakOnFirstHit != 0 {
                                                    current_block = 6058993197908835384;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    } else if (unsafe { (*cur).type_0 }) as u32 == type_0 as xmlElementType as u32 {
                        if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
                            if hasAxisRange != 0 as i32 {
                                pos += 1;
                                if pos == maxPos {
                                    hasNsNodes = 1 as i32;
                                    if xmlXPathNodeSetAddNs(seq, unsafe { (*xpctxt).node }, cur as xmlNsPtr)
                                        < 0 as i32
                                    {
                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                    }
                                    current_block = 16871635383312547059;
                                    break;
                                }
                            } else {
                                hasNsNodes = 1 as i32;
                                if xmlXPathNodeSetAddNs(seq, unsafe { (*xpctxt).node }, cur as xmlNsPtr)
                                    < 0 as i32
                                {
                                    (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                }
                                if breakOnFirstHit != 0 {
                                    current_block = 6058993197908835384;
                                    break;
                                }
                            }
                        } else if hasAxisRange != 0 as i32 {
                            pos += 1;
                            if pos == maxPos {
                                if (unsafe { addNode.expect("non-null function pointer")(seq, cur) }) < 0 as i32
                                {
                                    (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                }
                                current_block = 16871635383312547059;
                                break;
                            }
                        } else {
                            if (unsafe { addNode.expect("non-null function pointer")(seq, cur) }) < 0 as i32 {
                                (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                            }
                            if breakOnFirstHit != 0 {
                                current_block = 6058993197908835384;
                                break;
                            }
                        }
                    } else if type_0 as u32 == NODE_TYPE_TEXT as i32 as u32
                        && (unsafe { (*cur).type_0 }) as u32 == XML_CDATA_SECTION_NODE as i32 as u32
                    {
                        if hasAxisRange != 0 as i32 {
                            pos += 1;
                            if pos == maxPos {
                                if (unsafe { addNode.expect("non-null function pointer")(seq, cur) }) < 0 as i32
                                {
                                    (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                }
                                current_block = 16871635383312547059;
                                break;
                            }
                        } else {
                            if (unsafe { addNode.expect("non-null function pointer")(seq, cur) }) < 0 as i32 {
                                (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                            }
                            if breakOnFirstHit != 0 {
                                current_block = 6058993197908835384;
                                break;
                            }
                        }
                    }
                }
                2 => {
                    if (unsafe { (*cur).type_0 }) as u32 == XML_PI_NODE as i32 as u32
                        && (name.is_null() || (unsafe { xmlStrEqual(name, (*cur).name) }) != 0)
                    {
                        if hasAxisRange != 0 as i32 {
                            pos += 1;
                            if pos == maxPos {
                                if (unsafe { addNode.expect("non-null function pointer")(seq, cur) }) < 0 as i32
                                {
                                    (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                }
                                current_block = 16871635383312547059;
                                break;
                            }
                        } else {
                            if (unsafe { addNode.expect("non-null function pointer")(seq, cur) }) < 0 as i32 {
                                (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                            }
                            if breakOnFirstHit != 0 {
                                current_block = 6058993197908835384;
                                break;
                            }
                        }
                    }
                }
                3 => {
                    if axis as u32 == AXIS_ATTRIBUTE as i32 as u32 {
                        if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
                            if prefix.is_null() {
                                if hasAxisRange != 0 as i32 {
                                    pos += 1;
                                    if pos == maxPos {
                                        if (unsafe { addNode.expect("non-null function pointer")(seq, cur) })
                                            < 0 as i32
                                        {
                                            (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                        }
                                        current_block = 16871635383312547059;
                                        break;
                                    }
                                } else {
                                    if (unsafe { addNode.expect("non-null function pointer")(seq, cur) })
                                        < 0 as i32
                                    {
                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                    }
                                    if breakOnFirstHit != 0 {
                                        current_block = 6058993197908835384;
                                        break;
                                    }
                                }
                            } else if !(unsafe { (*cur).ns }).is_null()
                                && (unsafe { xmlStrEqual(URI, (*(*cur).ns).href) }) != 0
                            {
                                if hasAxisRange != 0 as i32 {
                                    pos += 1;
                                    if pos == maxPos {
                                        if (unsafe { addNode.expect("non-null function pointer")(seq, cur) })
                                            < 0 as i32
                                        {
                                            (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                        }
                                        current_block = 16871635383312547059;
                                        break;
                                    }
                                } else {
                                    if (unsafe { addNode.expect("non-null function pointer")(seq, cur) })
                                        < 0 as i32
                                    {
                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                    }
                                    if breakOnFirstHit != 0 {
                                        current_block = 6058993197908835384;
                                        break;
                                    }
                                }
                            }
                        }
                    } else if axis as u32 == AXIS_NAMESPACE as i32 as u32 {
                        if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
                            if hasAxisRange != 0 as i32 {
                                pos += 1;
                                if pos == maxPos {
                                    hasNsNodes = 1 as i32;
                                    if xmlXPathNodeSetAddNs(seq, unsafe { (*xpctxt).node }, cur as xmlNsPtr)
                                        < 0 as i32
                                    {
                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                    }
                                    current_block = 16871635383312547059;
                                    break;
                                }
                            } else {
                                hasNsNodes = 1 as i32;
                                if xmlXPathNodeSetAddNs(seq, unsafe { (*xpctxt).node }, cur as xmlNsPtr)
                                    < 0 as i32
                                {
                                    (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                }
                                if breakOnFirstHit != 0 {
                                    current_block = 6058993197908835384;
                                    break;
                                }
                            }
                        }
                    } else if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                        if prefix.is_null() {
                            if hasAxisRange != 0 as i32 {
                                pos += 1;
                                if pos == maxPos {
                                    if (unsafe { addNode.expect("non-null function pointer")(seq, cur) })
                                        < 0 as i32
                                    {
                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                    }
                                    current_block = 16871635383312547059;
                                    break;
                                }
                            } else {
                                if (unsafe { addNode.expect("non-null function pointer")(seq, cur) }) < 0 as i32
                                {
                                    (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                }
                                if breakOnFirstHit != 0 {
                                    current_block = 6058993197908835384;
                                    break;
                                }
                            }
                        } else if !(unsafe { (*cur).ns }).is_null() && (unsafe { xmlStrEqual(URI, (*(*cur).ns).href) }) != 0
                        {
                            if hasAxisRange != 0 as i32 {
                                pos += 1;
                                if pos == maxPos {
                                    if (unsafe { addNode.expect("non-null function pointer")(seq, cur) })
                                        < 0 as i32
                                    {
                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                    }
                                    current_block = 16871635383312547059;
                                    break;
                                }
                            } else {
                                if (unsafe { addNode.expect("non-null function pointer")(seq, cur) }) < 0 as i32
                                {
                                    (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                }
                                if breakOnFirstHit != 0 {
                                    current_block = 6058993197908835384;
                                    break;
                                }
                            }
                        }
                    }
                }
                4 => {
                    (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                        b"xpath.c\0" as *const u8 as *const i8,
                        12349 as i32,
                    ) });
                }
                5 => {
                    if axis as u32 == AXIS_ATTRIBUTE as i32 as u32 {
                        if (unsafe { (*cur).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32 {
                            current_block = 2652804691515851435;
                        } else {
                            current_block = 11911614146017124710;
                        }
                    } else if axis as u32 == AXIS_NAMESPACE as i32 as u32 {
                        if (unsafe { (*cur).type_0 }) as u32 != XML_NAMESPACE_DECL as i32 as u32 {
                            current_block = 2652804691515851435;
                        } else {
                            current_block = 11911614146017124710;
                        }
                    } else if (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
                        current_block = 2652804691515851435;
                    } else {
                        current_block = 11911614146017124710;
                    }
                    match current_block {
                        2652804691515851435 => {}
                        _ => match (unsafe { (*cur).type_0 }) as u32 {
                            1 => {
                                current_block = 373193326071211611;
                                match current_block {
                                    373193326071211611 => {
                                        if (unsafe { xmlStrEqual(name, (*cur).name) }) != 0 {
                                            if prefix.is_null() {
                                                if (unsafe { (*cur).ns }).is_null() {
                                                    if hasAxisRange != 0 as i32 {
                                                        pos += 1;
                                                        if pos == maxPos {
                                                            if (unsafe { addNode
                                                                .expect("non-null function pointer")(
                                                                seq, cur,
                                                            ) }) < 0 as i32
                                                            {
                                                                (unsafe { (*ctxt).error =
                                                                    XPATH_MEMORY_ERROR as i32 });
                                                            }
                                                            current_block = 16871635383312547059;
                                                            break;
                                                        }
                                                    } else {
                                                        if (unsafe { addNode
                                                            .expect("non-null function pointer")(
                                                            seq, cur,
                                                        ) }) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        if breakOnFirstHit != 0 {
                                                            current_block = 6058993197908835384;
                                                            break;
                                                        }
                                                    }
                                                }
                                            } else if !(unsafe { (*cur).ns }).is_null()
                                                && (unsafe { xmlStrEqual(URI, (*(*cur).ns).href) }) != 0
                                            {
                                                if hasAxisRange != 0 as i32 {
                                                    pos += 1;
                                                    if pos == maxPos {
                                                        if (unsafe { addNode
                                                            .expect("non-null function pointer")(
                                                            seq, cur,
                                                        ) }) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        current_block = 16871635383312547059;
                                                        break;
                                                    }
                                                } else {
                                                    if (unsafe { addNode.expect("non-null function pointer")(
                                                        seq, cur,
                                                    ) }) < 0 as i32
                                                    {
                                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                    }
                                                    if breakOnFirstHit != 0 {
                                                        current_block = 6058993197908835384;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    2629955293592203012 => {
                                        let mut attr: xmlAttrPtr = cur as xmlAttrPtr;
                                        if (unsafe { xmlStrEqual(name, (*attr).name) }) != 0 {
                                            if prefix.is_null() {
                                                if (unsafe { (*attr).ns }).is_null()
                                                    || (unsafe { (*(*attr).ns).prefix }).is_null()
                                                {
                                                    if hasAxisRange != 0 as i32 {
                                                        pos += 1;
                                                        if pos == maxPos {
                                                            if (unsafe { addNode
                                                                .expect("non-null function pointer")(
                                                                seq, cur,
                                                            ) }) < 0 as i32
                                                            {
                                                                (unsafe { (*ctxt).error =
                                                                    XPATH_MEMORY_ERROR as i32 });
                                                            }
                                                            current_block = 16871635383312547059;
                                                            break;
                                                        }
                                                    } else {
                                                        if (unsafe { addNode
                                                            .expect("non-null function pointer")(
                                                            seq, cur,
                                                        ) }) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        if breakOnFirstHit != 0 {
                                                            current_block = 6058993197908835384;
                                                            break;
                                                        }
                                                    }
                                                }
                                            } else if !(unsafe { (*attr).ns }).is_null()
                                                && (unsafe { xmlStrEqual(URI, (*(*attr).ns).href) }) != 0
                                            {
                                                if hasAxisRange != 0 as i32 {
                                                    pos += 1;
                                                    if pos == maxPos {
                                                        if (unsafe { addNode
                                                            .expect("non-null function pointer")(
                                                            seq, cur,
                                                        ) }) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        current_block = 16871635383312547059;
                                                        break;
                                                    }
                                                } else {
                                                    if (unsafe { addNode.expect("non-null function pointer")(
                                                        seq, cur,
                                                    ) }) < 0 as i32
                                                    {
                                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                    }
                                                    if breakOnFirstHit != 0 {
                                                        current_block = 6058993197908835384;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    _ => {
                                        if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
                                        {
                                            let mut ns: xmlNsPtr = cur as xmlNsPtr;
                                            if !(unsafe { (*ns).prefix }).is_null()
                                                && !name.is_null()
                                                && (unsafe { xmlStrEqual((*ns).prefix, name) }) != 0
                                            {
                                                if hasAxisRange != 0 as i32 {
                                                    pos += 1;
                                                    if pos == maxPos {
                                                        hasNsNodes = 1 as i32;
                                                        if xmlXPathNodeSetAddNs(
                                                            seq,
                                                            unsafe { (*xpctxt).node },
                                                            cur as xmlNsPtr,
                                                        ) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        current_block = 16871635383312547059;
                                                        break;
                                                    }
                                                } else {
                                                    hasNsNodes = 1 as i32;
                                                    if xmlXPathNodeSetAddNs(
                                                        seq,
                                                        unsafe { (*xpctxt).node },
                                                        cur as xmlNsPtr,
                                                    ) < 0 as i32
                                                    {
                                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                    }
                                                    if breakOnFirstHit != 0 {
                                                        current_block = 6058993197908835384;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            2 => {
                                current_block = 2629955293592203012;
                                match current_block {
                                    373193326071211611 => {
                                        if (unsafe { xmlStrEqual(name, (*cur).name) }) != 0 {
                                            if prefix.is_null() {
                                                if (unsafe { (*cur).ns }).is_null() {
                                                    if hasAxisRange != 0 as i32 {
                                                        pos += 1;
                                                        if pos == maxPos {
                                                            if (unsafe { addNode
                                                                .expect("non-null function pointer")(
                                                                seq, cur,
                                                            ) }) < 0 as i32
                                                            {
                                                                (unsafe { (*ctxt).error =
                                                                    XPATH_MEMORY_ERROR as i32 });
                                                            }
                                                            current_block = 16871635383312547059;
                                                            break;
                                                        }
                                                    } else {
                                                        if (unsafe { addNode
                                                            .expect("non-null function pointer")(
                                                            seq, cur,
                                                        ) }) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        if breakOnFirstHit != 0 {
                                                            current_block = 6058993197908835384;
                                                            break;
                                                        }
                                                    }
                                                }
                                            } else if !(unsafe { (*cur).ns }).is_null()
                                                && (unsafe { xmlStrEqual(URI, (*(*cur).ns).href) }) != 0
                                            {
                                                if hasAxisRange != 0 as i32 {
                                                    pos += 1;
                                                    if pos == maxPos {
                                                        if (unsafe { addNode
                                                            .expect("non-null function pointer")(
                                                            seq, cur,
                                                        ) }) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        current_block = 16871635383312547059;
                                                        break;
                                                    }
                                                } else {
                                                    if (unsafe { addNode.expect("non-null function pointer")(
                                                        seq, cur,
                                                    ) }) < 0 as i32
                                                    {
                                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                    }
                                                    if breakOnFirstHit != 0 {
                                                        current_block = 6058993197908835384;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    2629955293592203012 => {
                                        let mut attr: xmlAttrPtr = cur as xmlAttrPtr;
                                        if (unsafe { xmlStrEqual(name, (*attr).name) }) != 0 {
                                            if prefix.is_null() {
                                                if (unsafe { (*attr).ns }).is_null()
                                                    || (unsafe { (*(*attr).ns).prefix }).is_null()
                                                {
                                                    if hasAxisRange != 0 as i32 {
                                                        pos += 1;
                                                        if pos == maxPos {
                                                            if (unsafe { addNode
                                                                .expect("non-null function pointer")(
                                                                seq, cur,
                                                            ) }) < 0 as i32
                                                            {
                                                                (unsafe { (*ctxt).error =
                                                                    XPATH_MEMORY_ERROR as i32 });
                                                            }
                                                            current_block = 16871635383312547059;
                                                            break;
                                                        }
                                                    } else {
                                                        if (unsafe { addNode
                                                            .expect("non-null function pointer")(
                                                            seq, cur,
                                                        ) }) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        if breakOnFirstHit != 0 {
                                                            current_block = 6058993197908835384;
                                                            break;
                                                        }
                                                    }
                                                }
                                            } else if !(unsafe { (*attr).ns }).is_null()
                                                && (unsafe { xmlStrEqual(URI, (*(*attr).ns).href) }) != 0
                                            {
                                                if hasAxisRange != 0 as i32 {
                                                    pos += 1;
                                                    if pos == maxPos {
                                                        if (unsafe { addNode
                                                            .expect("non-null function pointer")(
                                                            seq, cur,
                                                        ) }) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        current_block = 16871635383312547059;
                                                        break;
                                                    }
                                                } else {
                                                    if (unsafe { addNode.expect("non-null function pointer")(
                                                        seq, cur,
                                                    ) }) < 0 as i32
                                                    {
                                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                    }
                                                    if breakOnFirstHit != 0 {
                                                        current_block = 6058993197908835384;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    _ => {
                                        if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
                                        {
                                            let mut ns: xmlNsPtr = cur as xmlNsPtr;
                                            if !(unsafe { (*ns).prefix }).is_null()
                                                && !name.is_null()
                                                && (unsafe { xmlStrEqual((*ns).prefix, name) }) != 0
                                            {
                                                if hasAxisRange != 0 as i32 {
                                                    pos += 1;
                                                    if pos == maxPos {
                                                        hasNsNodes = 1 as i32;
                                                        if xmlXPathNodeSetAddNs(
                                                            seq,
                                                            unsafe { (*xpctxt).node },
                                                            cur as xmlNsPtr,
                                                        ) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        current_block = 16871635383312547059;
                                                        break;
                                                    }
                                                } else {
                                                    hasNsNodes = 1 as i32;
                                                    if xmlXPathNodeSetAddNs(
                                                        seq,
                                                        unsafe { (*xpctxt).node },
                                                        cur as xmlNsPtr,
                                                    ) < 0 as i32
                                                    {
                                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                    }
                                                    if breakOnFirstHit != 0 {
                                                        current_block = 6058993197908835384;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            18 => {
                                current_block = 160406893464850698;
                                match current_block {
                                    373193326071211611 => {
                                        if (unsafe { xmlStrEqual(name, (*cur).name) }) != 0 {
                                            if prefix.is_null() {
                                                if (unsafe { (*cur).ns }).is_null() {
                                                    if hasAxisRange != 0 as i32 {
                                                        pos += 1;
                                                        if pos == maxPos {
                                                            if (unsafe { addNode
                                                                .expect("non-null function pointer")(
                                                                seq, cur,
                                                            ) }) < 0 as i32
                                                            {
                                                                (unsafe { (*ctxt).error =
                                                                    XPATH_MEMORY_ERROR as i32 });
                                                            }
                                                            current_block = 16871635383312547059;
                                                            break;
                                                        }
                                                    } else {
                                                        if (unsafe { addNode
                                                            .expect("non-null function pointer")(
                                                            seq, cur,
                                                        ) }) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        if breakOnFirstHit != 0 {
                                                            current_block = 6058993197908835384;
                                                            break;
                                                        }
                                                    }
                                                }
                                            } else if !(unsafe { (*cur).ns }).is_null()
                                                && (unsafe { xmlStrEqual(URI, (*(*cur).ns).href) }) != 0
                                            {
                                                if hasAxisRange != 0 as i32 {
                                                    pos += 1;
                                                    if pos == maxPos {
                                                        if (unsafe { addNode
                                                            .expect("non-null function pointer")(
                                                            seq, cur,
                                                        ) }) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        current_block = 16871635383312547059;
                                                        break;
                                                    }
                                                } else {
                                                    if (unsafe { addNode.expect("non-null function pointer")(
                                                        seq, cur,
                                                    ) }) < 0 as i32
                                                    {
                                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                    }
                                                    if breakOnFirstHit != 0 {
                                                        current_block = 6058993197908835384;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    2629955293592203012 => {
                                        let mut attr: xmlAttrPtr = cur as xmlAttrPtr;
                                        if (unsafe { xmlStrEqual(name, (*attr).name) }) != 0 {
                                            if prefix.is_null() {
                                                if (unsafe { (*attr).ns }).is_null()
                                                    || (unsafe { (*(*attr).ns).prefix }).is_null()
                                                {
                                                    if hasAxisRange != 0 as i32 {
                                                        pos += 1;
                                                        if pos == maxPos {
                                                            if (unsafe { addNode
                                                                .expect("non-null function pointer")(
                                                                seq, cur,
                                                            ) }) < 0 as i32
                                                            {
                                                                (unsafe { (*ctxt).error =
                                                                    XPATH_MEMORY_ERROR as i32 });
                                                            }
                                                            current_block = 16871635383312547059;
                                                            break;
                                                        }
                                                    } else {
                                                        if (unsafe { addNode
                                                            .expect("non-null function pointer")(
                                                            seq, cur,
                                                        ) }) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        if breakOnFirstHit != 0 {
                                                            current_block = 6058993197908835384;
                                                            break;
                                                        }
                                                    }
                                                }
                                            } else if !(unsafe { (*attr).ns }).is_null()
                                                && (unsafe { xmlStrEqual(URI, (*(*attr).ns).href) }) != 0
                                            {
                                                if hasAxisRange != 0 as i32 {
                                                    pos += 1;
                                                    if pos == maxPos {
                                                        if (unsafe { addNode
                                                            .expect("non-null function pointer")(
                                                            seq, cur,
                                                        ) }) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        current_block = 16871635383312547059;
                                                        break;
                                                    }
                                                } else {
                                                    if (unsafe { addNode.expect("non-null function pointer")(
                                                        seq, cur,
                                                    ) }) < 0 as i32
                                                    {
                                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                    }
                                                    if breakOnFirstHit != 0 {
                                                        current_block = 6058993197908835384;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    _ => {
                                        if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
                                        {
                                            let mut ns: xmlNsPtr = cur as xmlNsPtr;
                                            if !(unsafe { (*ns).prefix }).is_null()
                                                && !name.is_null()
                                                && (unsafe { xmlStrEqual((*ns).prefix, name) }) != 0
                                            {
                                                if hasAxisRange != 0 as i32 {
                                                    pos += 1;
                                                    if pos == maxPos {
                                                        hasNsNodes = 1 as i32;
                                                        if xmlXPathNodeSetAddNs(
                                                            seq,
                                                            unsafe { (*xpctxt).node },
                                                            cur as xmlNsPtr,
                                                        ) < 0 as i32
                                                        {
                                                            (unsafe { (*ctxt).error =
                                                                XPATH_MEMORY_ERROR as i32 });
                                                        }
                                                        current_block = 16871635383312547059;
                                                        break;
                                                    }
                                                } else {
                                                    hasNsNodes = 1 as i32;
                                                    if xmlXPathNodeSetAddNs(
                                                        seq,
                                                        unsafe { (*xpctxt).node },
                                                        cur as xmlNsPtr,
                                                    ) < 0 as i32
                                                    {
                                                        (unsafe { (*ctxt).error = XPATH_MEMORY_ERROR as i32 });
                                                    }
                                                    if breakOnFirstHit != 0 {
                                                        current_block = 6058993197908835384;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        },
                    }
                }
                _ => {}
            }
            if !(!cur.is_null() && (unsafe { (*ctxt).error }) == XPATH_EXPRESSION_OK as i32) {
                current_block = 16313108704606884446;
                break;
            }
        }
        match current_block {
            6058993197908835384 => {
                if outSeq.is_null() {
                    outSeq = seq;
                    seq = 0 as xmlNodeSetPtr;
                } else {
                    outSeq = unsafe { mergeAndClear.expect("non-null function pointer")(outSeq, seq) };
                }
                break;
            }
            16313108704606884446 => {
                if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                    break;
                }
                if !predOp.is_null() && (unsafe { (*seq).nodeNr }) > 0 as i32 {
                    if hasPredicateRange != 0 as i32 {
                        xmlXPathCompOpEvalPredicate(ctxt, predOp, seq, maxPos, maxPos, hasNsNodes);
                    } else {
                        xmlXPathCompOpEvalPredicate(
                            ctxt,
                            predOp,
                            seq,
                            1 as i32,
                            unsafe { (*seq).nodeNr },
                            hasNsNodes,
                        );
                    }
                    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                        total = 0 as i32;
                        break;
                    }
                }
                if !((unsafe { (*seq).nodeNr }) > 0 as i32) {
                    continue;
                }
                if outSeq.is_null() {
                    outSeq = seq;
                    seq = 0 as xmlNodeSetPtr;
                } else {
                    outSeq = unsafe { mergeAndClear.expect("non-null function pointer")(outSeq, seq) };
                }
                if toBool != 0 {
                    break;
                }
            }
            _ => {
                if outSeq.is_null() {
                    outSeq = seq;
                    seq = 0 as xmlNodeSetPtr;
                } else {
                    outSeq = unsafe { mergeAndClear.expect("non-null function pointer")(outSeq, seq) };
                }
                if toBool != 0 {
                    break;
                }
            }
        }
    }
    if (unsafe { (*obj).boolval }) != 0 && !(unsafe { (*obj).user }).is_null() {
        (unsafe { (*(*ctxt).value).boolval = 1 as i32 });
        let fresh345 = unsafe { &mut ((*(*ctxt).value).user) };
        *fresh345 = unsafe { (*obj).user };
        let fresh346 = unsafe { &mut ((*obj).user) };
        *fresh346 = 0 as *mut libc::c_void;
        (unsafe { (*obj).boolval = 0 as i32 });
    }
    xmlXPathReleaseObject(xpctxt, obj);
    if outSeq.is_null() {
        if !seq.is_null() && (unsafe { (*seq).nodeNr }) == 0 as i32 {
            outSeq = seq;
        } else {
            outSeq = xmlXPathNodeSetCreate(0 as xmlNodePtr);
        }
    }
    if !seq.is_null() && seq != outSeq {
        xmlXPathFreeNodeSet(seq);
    }
    valuePush(ctxt, xmlXPathCacheWrapNodeSet(xpctxt, outSeq));
    let fresh347 = unsafe { &mut ((*xpctxt).node) };
    *fresh347 = oldContextNode;
    if !(unsafe { (*xpctxt).tmpNsList }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*xpctxt).tmpNsList as *mut libc::c_void) });
        let fresh348 = unsafe { &mut ((*xpctxt).tmpNsList) };
        *fresh348 = 0 as *mut xmlNsPtr;
    }
    return total;
}
extern "C" fn xmlXPathCompOpEvalFirst(
    mut ctxt: xmlXPathParserContextPtr,
    mut op: xmlXPathStepOpPtr,
    mut first: *mut xmlNodePtr,
) -> i32 {
    let mut total: i32 = 0 as i32;
    let mut cur: i32 = 0;
    let mut comp: xmlXPathCompExprPtr = 0 as *mut xmlXPathCompExpr;
    let mut arg1: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut arg2: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return 0 as i32;
    }
    if (unsafe { (*(*ctxt).context).opLimit }) != 0 as i32 as u64
        && xmlXPathCheckOpLimit(ctxt, 1 as i32 as u64) < 0 as i32
    {
        return 0 as i32;
    }
    if (unsafe { (*(*ctxt).context).depth }) >= 5000 as i32 {
        xmlXPathErr(ctxt, XPATH_RECURSION_LIMIT_EXCEEDED as i32);
        return 0 as i32;
    }
    (unsafe { (*(*ctxt).context).depth += 1 as i32 });
    comp = unsafe { (*ctxt).comp };
    match (unsafe { (*op).op }) as u32 {
        0 => {}
        7 => {
            total = xmlXPathCompOpEvalFirst(
                ctxt,
                unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) },
                first,
            );
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            if !(unsafe { (*ctxt).value }).is_null()
                && (unsafe { (*(*ctxt).value).type_0 }) as u32 == XPATH_NODESET as i32 as u32
                && !(unsafe { (*(*ctxt).value).nodesetval }).is_null()
                && (unsafe { (*(*(*ctxt).value).nodesetval).nodeNr }) >= 1 as i32
            {
                if (unsafe { (*(*(*ctxt).value).nodesetval).nodeNr }) > 1 as i32 {
                    xmlXPathNodeSetSort(unsafe { (*(*ctxt).value).nodesetval });
                }
                (unsafe { *first = *((*(*(*ctxt).value).nodesetval).nodeTab).offset(0 as i32 as isize) });
            }
            cur = xmlXPathCompOpEvalFirst(
                ctxt,
                unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) },
                first,
            );
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            arg2 = valuePop(ctxt);
            arg1 = valuePop(ctxt);
            if arg1.is_null()
                || (unsafe { (*arg1).type_0 }) as u32 != XPATH_NODESET as i32 as u32
                || arg2.is_null()
                || (unsafe { (*arg2).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            {
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
                xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
                return 0 as i32;
            }
            if (unsafe { (*(*ctxt).context).opLimit }) != 0 as i32 as u64
                && (!(unsafe { (*arg1).nodesetval }).is_null()
                    && xmlXPathCheckOpLimit(ctxt, (unsafe { (*(*arg1).nodesetval).nodeNr }) as u64) < 0 as i32
                    || !(unsafe { (*arg2).nodesetval }).is_null()
                        && xmlXPathCheckOpLimit(ctxt, (unsafe { (*(*arg2).nodesetval).nodeNr }) as u64)
                            < 0 as i32)
            {
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
            } else {
                let fresh349 = unsafe { &mut ((*arg1).nodesetval) };
                *fresh349 = xmlXPathNodeSetMerge(unsafe { (*arg1).nodesetval }, unsafe { (*arg2).nodesetval });
                valuePush(ctxt, arg1);
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
                if total > cur {
                    xmlXPathCompSwap(op);
                }
                total += cur;
            }
        }
        8 => {
            xmlXPathRoot(ctxt);
        }
        9 => {
            if (unsafe { (*op).ch1 }) != -(1 as i32) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
            }
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            if (unsafe { (*op).ch2 }) != -(1 as i32) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) });
            }
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            valuePush(
                ctxt,
                xmlXPathCacheNewNodeSet(unsafe { (*ctxt).context }, unsafe { (*(*ctxt).context).node }),
            );
        }
        10 => {
            if !((unsafe { (*op).ch1 }) == -(1 as i32)) {
                total = xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
                if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                    return 0 as i32;
                }
                total +=
                    xmlXPathNodeCollectAndTest(ctxt, op, first, 0 as *mut xmlNodePtr, 0 as i32);
            }
        }
        11 => {
            valuePush(
                ctxt,
                xmlXPathCacheObjectCopy(unsafe { (*ctxt).context }, (unsafe { (*op).value4 }) as xmlXPathObjectPtr),
            );
        }
        17 => {
            if (unsafe { (*op).ch1 }) != -(1 as i32) {
                total += xmlXPathCompOpEvalFirst(
                    ctxt,
                    unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) },
                    first,
                );
            }
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            if !(unsafe { (*ctxt).value }).is_null()
                && (unsafe { (*(*ctxt).value).type_0 }) as u32 == XPATH_NODESET as i32 as u32
                && !(unsafe { (*(*ctxt).value).nodesetval }).is_null()
                && (unsafe { (*(*(*ctxt).value).nodesetval).nodeNr }) > 1 as i32
            {
                xmlXPathNodeSetSort(unsafe { (*(*ctxt).value).nodesetval });
            }
        }
        16 => {
            total += xmlXPathCompOpEvalFilterFirst(ctxt, op, first);
        }
        _ => {
            total += xmlXPathCompOpEval(ctxt, op);
        }
    }
    (unsafe { (*(*ctxt).context).depth -= 1 as i32 });
    return total;
}
extern "C" fn xmlXPathCompOpEvalLast(
    mut ctxt: xmlXPathParserContextPtr,
    mut op: xmlXPathStepOpPtr,
    mut last: *mut xmlNodePtr,
) -> i32 {
    let mut total: i32 = 0 as i32;
    let mut cur: i32 = 0;
    let mut comp: xmlXPathCompExprPtr = 0 as *mut xmlXPathCompExpr;
    let mut arg1: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut arg2: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return 0 as i32;
    }
    if (unsafe { (*(*ctxt).context).opLimit }) != 0 as i32 as u64
        && xmlXPathCheckOpLimit(ctxt, 1 as i32 as u64) < 0 as i32
    {
        return 0 as i32;
    }
    if (unsafe { (*(*ctxt).context).depth }) >= 5000 as i32 {
        xmlXPathErr(ctxt, XPATH_RECURSION_LIMIT_EXCEEDED as i32);
        return 0 as i32;
    }
    (unsafe { (*(*ctxt).context).depth += 1 as i32 });
    comp = unsafe { (*ctxt).comp };
    match (unsafe { (*op).op }) as u32 {
        0 => {}
        7 => {
            total = xmlXPathCompOpEvalLast(
                ctxt,
                unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) },
                last,
            );
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            if !(unsafe { (*ctxt).value }).is_null()
                && (unsafe { (*(*ctxt).value).type_0 }) as u32 == XPATH_NODESET as i32 as u32
                && !(unsafe { (*(*ctxt).value).nodesetval }).is_null()
                && (unsafe { (*(*(*ctxt).value).nodesetval).nodeNr }) >= 1 as i32
            {
                if (unsafe { (*(*(*ctxt).value).nodesetval).nodeNr }) > 1 as i32 {
                    xmlXPathNodeSetSort(unsafe { (*(*ctxt).value).nodesetval });
                }
                (unsafe { *last = *((*(*(*ctxt).value).nodesetval).nodeTab)
                    .offset(((*(*(*ctxt).value).nodesetval).nodeNr - 1 as i32) as isize) });
            }
            cur = xmlXPathCompOpEvalLast(
                ctxt,
                unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) },
                last,
            );
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            let _ = !(unsafe { (*ctxt).value }).is_null()
                && (unsafe { (*(*ctxt).value).type_0 }) as u32 == XPATH_NODESET as i32 as u32
                && !(unsafe { (*(*ctxt).value).nodesetval }).is_null()
                && (unsafe { (*(*(*ctxt).value).nodesetval).nodeNr }) >= 1 as i32;
            arg2 = valuePop(ctxt);
            arg1 = valuePop(ctxt);
            if arg1.is_null()
                || (unsafe { (*arg1).type_0 }) as u32 != XPATH_NODESET as i32 as u32
                || arg2.is_null()
                || (unsafe { (*arg2).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            {
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
                xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
                return 0 as i32;
            }
            if (unsafe { (*(*ctxt).context).opLimit }) != 0 as i32 as u64
                && (!(unsafe { (*arg1).nodesetval }).is_null()
                    && xmlXPathCheckOpLimit(ctxt, (unsafe { (*(*arg1).nodesetval).nodeNr }) as u64) < 0 as i32
                    || !(unsafe { (*arg2).nodesetval }).is_null()
                        && xmlXPathCheckOpLimit(ctxt, (unsafe { (*(*arg2).nodesetval).nodeNr }) as u64)
                            < 0 as i32)
            {
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
            } else {
                let fresh350 = unsafe { &mut ((*arg1).nodesetval) };
                *fresh350 = xmlXPathNodeSetMerge(unsafe { (*arg1).nodesetval }, unsafe { (*arg2).nodesetval });
                valuePush(ctxt, arg1);
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
                if total > cur {
                    xmlXPathCompSwap(op);
                }
                total += cur;
            }
        }
        8 => {
            xmlXPathRoot(ctxt);
        }
        9 => {
            if (unsafe { (*op).ch1 }) != -(1 as i32) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
            }
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            if (unsafe { (*op).ch2 }) != -(1 as i32) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) });
            }
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            valuePush(
                ctxt,
                xmlXPathCacheNewNodeSet(unsafe { (*ctxt).context }, unsafe { (*(*ctxt).context).node }),
            );
        }
        10 => {
            if !((unsafe { (*op).ch1 }) == -(1 as i32)) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
                if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                    return 0 as i32;
                }
                total += xmlXPathNodeCollectAndTest(ctxt, op, 0 as *mut xmlNodePtr, last, 0 as i32);
            }
        }
        11 => {
            valuePush(
                ctxt,
                xmlXPathCacheObjectCopy(unsafe { (*ctxt).context }, (unsafe { (*op).value4 }) as xmlXPathObjectPtr),
            );
        }
        17 => {
            if (unsafe { (*op).ch1 }) != -(1 as i32) {
                total += xmlXPathCompOpEvalLast(
                    ctxt,
                    unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) },
                    last,
                );
            }
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            if !(unsafe { (*ctxt).value }).is_null()
                && (unsafe { (*(*ctxt).value).type_0 }) as u32 == XPATH_NODESET as i32 as u32
                && !(unsafe { (*(*ctxt).value).nodesetval }).is_null()
                && (unsafe { (*(*(*ctxt).value).nodesetval).nodeNr }) > 1 as i32
            {
                xmlXPathNodeSetSort(unsafe { (*(*ctxt).value).nodesetval });
            }
        }
        _ => {
            total += xmlXPathCompOpEval(ctxt, op);
        }
    }
    (unsafe { (*(*ctxt).context).depth -= 1 as i32 });
    return total;
}
extern "C" fn xmlXPathCompOpEvalFilterFirst(
    mut ctxt: xmlXPathParserContextPtr,
    mut op: xmlXPathStepOpPtr,
    mut first: *mut xmlNodePtr,
) -> i32 {
    let mut total: i32 = 0 as i32;
    let mut comp: xmlXPathCompExprPtr = 0 as *mut xmlXPathCompExpr;
    let mut set: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return 0 as i32;
    }
    comp = unsafe { (*ctxt).comp };
    if (unsafe { (*op).ch1 }) != -(1 as i32)
        && (unsafe { (*op).ch2 }) != -(1 as i32)
        && (unsafe { (*((*comp).steps).offset((*op).ch1 as isize)).op }) as u32 == XPATH_OP_SORT as i32 as u32
        && (unsafe { (*((*comp).steps).offset((*op).ch2 as isize)).op }) as u32 == XPATH_OP_SORT as i32 as u32
    {
        let mut f: i32 = unsafe { (*((*comp).steps).offset((*op).ch2 as isize)).ch1 };
        if f != -(1 as i32)
            && (unsafe { (*((*comp).steps).offset(f as isize)).op }) as u32 == XPATH_OP_FUNCTION as i32 as u32
            && (unsafe { (*((*comp).steps).offset(f as isize)).value5 }).is_null()
            && (unsafe { (*((*comp).steps).offset(f as isize)).value }) == 0 as i32
            && !(unsafe { (*((*comp).steps).offset(f as isize)).value4 }).is_null()
            && (unsafe { xmlStrEqual(
                (*((*comp).steps).offset(f as isize)).value4 as *const xmlChar,
                b"last\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) != 0
        {
            let mut last: xmlNodePtr = 0 as xmlNodePtr;
            total += xmlXPathCompOpEvalLast(
                ctxt,
                unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) },
                &mut last,
            );
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            if !(unsafe { (*ctxt).value }).is_null()
                && (unsafe { (*(*ctxt).value).type_0 }) as u32 == XPATH_NODESET as i32 as u32
                && !(unsafe { (*(*ctxt).value).nodesetval }).is_null()
                && !(unsafe { (*(*(*ctxt).value).nodesetval).nodeTab }).is_null()
                && (unsafe { (*(*(*ctxt).value).nodesetval).nodeNr }) > 1 as i32
            {
                xmlXPathNodeSetKeepLast(unsafe { (*(*ctxt).value).nodesetval });
                (unsafe { *first = *(*(*(*ctxt).value).nodesetval).nodeTab });
            }
            return total;
        }
    }
    if (unsafe { (*op).ch1 }) != -(1 as i32) {
        total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
    }
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return 0 as i32;
    }
    if (unsafe { (*op).ch2 }) == -(1 as i32) {
        return total;
    }
    if (unsafe { (*ctxt).value }).is_null() {
        return total;
    }
    if (unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NODESET as i32 as u32 {
        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
        return 0 as i32;
    }
    set = unsafe { (*(*ctxt).value).nodesetval };
    if !set.is_null() {
        xmlXPathNodeSetFilter(ctxt, set, unsafe { (*op).ch2 }, 1 as i32, 1 as i32, 1 as i32);
        if (unsafe { (*set).nodeNr }) > 0 as i32 {
            (unsafe { *first = *((*set).nodeTab).offset(0 as i32 as isize) });
        }
    }
    return total;
}
extern "C" fn xmlXPathCompOpEval(
    mut ctxt: xmlXPathParserContextPtr,
    mut op: xmlXPathStepOpPtr,
) -> i32 {
    let mut total: i32 = 0 as i32;
    let mut equal: i32 = 0;
    let mut ret: i32 = 0;
    let mut comp: xmlXPathCompExprPtr = 0 as *mut xmlXPathCompExpr;
    let mut arg1: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut arg2: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        return 0 as i32;
    }
    if (unsafe { (*(*ctxt).context).opLimit }) != 0 as i32 as u64
        && xmlXPathCheckOpLimit(ctxt, 1 as i32 as u64) < 0 as i32
    {
        return 0 as i32;
    }
    if (unsafe { (*(*ctxt).context).depth }) >= 5000 as i32 {
        xmlXPathErr(ctxt, XPATH_RECURSION_LIMIT_EXCEEDED as i32);
        return 0 as i32;
    }
    (unsafe { (*(*ctxt).context).depth += 1 as i32 });
    comp = unsafe { (*ctxt).comp };
    let mut current_block_226: u64;
    match (unsafe { (*op).op }) as u32 {
        0 => {}
        1 => {
            total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            xmlXPathBooleanFunction(ctxt, 1 as i32);
            if !((unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).boolval }) == 0 as i32) {
                arg2 = valuePop(ctxt);
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) });
                if (unsafe { (*ctxt).error }) != 0 {
                    xmlXPathFreeObject(arg2);
                } else {
                    xmlXPathBooleanFunction(ctxt, 1 as i32);
                    if !(unsafe { (*ctxt).value }).is_null() {
                        (unsafe { (*(*ctxt).value).boolval &= (*arg2).boolval });
                    }
                    xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
                }
            }
        }
        2 => {
            total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            xmlXPathBooleanFunction(ctxt, 1 as i32);
            if !((unsafe { (*ctxt).value }).is_null() || (unsafe { (*(*ctxt).value).boolval }) == 1 as i32) {
                arg2 = valuePop(ctxt);
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) });
                if (unsafe { (*ctxt).error }) != 0 {
                    xmlXPathFreeObject(arg2);
                } else {
                    xmlXPathBooleanFunction(ctxt, 1 as i32);
                    if !(unsafe { (*ctxt).value }).is_null() {
                        (unsafe { (*(*ctxt).value).boolval |= (*arg2).boolval });
                    }
                    xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
                }
            }
        }
        3 => {
            total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) });
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            if (unsafe { (*op).value }) != 0 {
                equal = xmlXPathEqualValues(ctxt);
            } else {
                equal = xmlXPathNotEqualValues(ctxt);
            }
            valuePush(ctxt, xmlXPathCacheNewBoolean(unsafe { (*ctxt).context }, equal));
        }
        4 => {
            total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) });
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            ret = xmlXPathCompareValues(ctxt, unsafe { (*op).value }, unsafe { (*op).value2 });
            valuePush(ctxt, xmlXPathCacheNewBoolean(unsafe { (*ctxt).context }, ret));
        }
        5 => {
            total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            if (unsafe { (*op).ch2 }) != -(1 as i32) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) });
            }
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            if (unsafe { (*op).value }) == 0 as i32 {
                xmlXPathSubValues(ctxt);
            } else if (unsafe { (*op).value }) == 1 as i32 {
                xmlXPathAddValues(ctxt);
            } else if (unsafe { (*op).value }) == 2 as i32 {
                xmlXPathValueFlipSign(ctxt);
            } else if (unsafe { (*op).value }) == 3 as i32 {
                if !(unsafe { (*ctxt).value }).is_null()
                    && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32
                {
                    xmlXPathNumberFunction(ctxt, 1 as i32);
                }
                if (unsafe { (*ctxt).value }).is_null()
                    || (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_NUMBER as i32 as u32
                {
                    xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
                    return 0 as i32;
                }
            }
        }
        6 => {
            total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) });
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            if (unsafe { (*op).value }) == 0 as i32 {
                xmlXPathMultValues(ctxt);
            } else if (unsafe { (*op).value }) == 1 as i32 {
                xmlXPathDivValues(ctxt);
            } else if (unsafe { (*op).value }) == 2 as i32 {
                xmlXPathModValues(ctxt);
            }
        }
        7 => {
            total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) });
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            arg2 = valuePop(ctxt);
            arg1 = valuePop(ctxt);
            if arg1.is_null()
                || (unsafe { (*arg1).type_0 }) as u32 != XPATH_NODESET as i32 as u32
                || arg2.is_null()
                || (unsafe { (*arg2).type_0 }) as u32 != XPATH_NODESET as i32 as u32
            {
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
                xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
                return 0 as i32;
            }
            if (unsafe { (*(*ctxt).context).opLimit }) != 0 as i32 as u64
                && (!(unsafe { (*arg1).nodesetval }).is_null()
                    && xmlXPathCheckOpLimit(ctxt, (unsafe { (*(*arg1).nodesetval).nodeNr }) as u64) < 0 as i32
                    || !(unsafe { (*arg2).nodesetval }).is_null()
                        && xmlXPathCheckOpLimit(ctxt, (unsafe { (*(*arg2).nodesetval).nodeNr }) as u64)
                            < 0 as i32)
            {
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg1);
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
            } else {
                if (unsafe { (*arg1).nodesetval }).is_null()
                    || !(unsafe { (*arg2).nodesetval }).is_null() && (unsafe { (*(*arg2).nodesetval).nodeNr }) != 0 as i32
                {
                    let fresh351 = unsafe { &mut ((*arg1).nodesetval) };
                    *fresh351 = xmlXPathNodeSetMerge(unsafe { (*arg1).nodesetval }, unsafe { (*arg2).nodesetval });
                }
                valuePush(ctxt, arg1);
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, arg2);
            }
        }
        8 => {
            xmlXPathRoot(ctxt);
        }
        9 => {
            if (unsafe { (*op).ch1 }) != -(1 as i32) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
            }
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            if (unsafe { (*op).ch2 }) != -(1 as i32) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) });
            }
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            valuePush(
                ctxt,
                xmlXPathCacheNewNodeSet(unsafe { (*ctxt).context }, unsafe { (*(*ctxt).context).node }),
            );
        }
        10 => {
            if !((unsafe { (*op).ch1 }) == -(1 as i32)) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
                if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                    return 0 as i32;
                }
                total += xmlXPathNodeCollectAndTest(
                    ctxt,
                    op,
                    0 as *mut xmlNodePtr,
                    0 as *mut xmlNodePtr,
                    0 as i32,
                );
            }
        }
        11 => {
            valuePush(
                ctxt,
                xmlXPathCacheObjectCopy(unsafe { (*ctxt).context }, (unsafe { (*op).value4 }) as xmlXPathObjectPtr),
            );
        }
        12 => {
            let mut val: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
            if (unsafe { (*op).ch1 }) != -(1 as i32) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
            }
            if (unsafe { (*op).value5 }).is_null() {
                val = xmlXPathVariableLookup(unsafe { (*ctxt).context }, (unsafe { (*op).value4 }) as *const xmlChar);
                if val.is_null() {
                    xmlXPathErr(ctxt, XPATH_UNDEF_VARIABLE_ERROR as i32);
                    return 0 as i32;
                }
                valuePush(ctxt, val);
            } else {
                let mut URI: *const xmlChar = 0 as *const xmlChar;
                URI = xmlXPathNsLookup(unsafe { (*ctxt).context }, (unsafe { (*op).value5 }) as *const xmlChar);
                if URI.is_null() {
                    (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"xmlXPathCompOpEval: variable %s bound to undefined prefix %s\n\0"
                            as *const u8 as *const i8,
                        (*op).value4 as *mut i8,
                        (*op).value5 as *mut i8,
                    ) });
                    (unsafe { (*ctxt).error = XPATH_UNDEF_PREFIX_ERROR as i32 });
                } else {
                    val = xmlXPathVariableLookupNS(
                        unsafe { (*ctxt).context },
                        (unsafe { (*op).value4 }) as *const xmlChar,
                        URI,
                    );
                    if val.is_null() {
                        xmlXPathErr(ctxt, XPATH_UNDEF_VARIABLE_ERROR as i32);
                        return 0 as i32;
                    }
                    valuePush(ctxt, val);
                }
            }
        }
        13 => {
            let mut func: xmlXPathFunction = None;
            let mut oldFunc: *const xmlChar = 0 as *const xmlChar;
            let mut oldFuncURI: *const xmlChar = 0 as *const xmlChar;
            let mut i: i32 = 0;
            let mut frame: i32 = 0;
            frame = xmlXPathSetFrame(ctxt);
            if (unsafe { (*op).ch1 }) != -(1 as i32) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
                if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                    xmlXPathPopFrame(ctxt, frame);
                    current_block_226 = 11940120049376251063;
                } else {
                    current_block_226 = 6535105651042291885;
                }
            } else {
                current_block_226 = 6535105651042291885;
            }
            match current_block_226 {
                11940120049376251063 => {}
                _ => {
                    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + (unsafe { (*op).value }) {
                        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                            *__xmlGenericErrorContext(),
                            b"xmlXPathCompOpEval: parameter error\n\0" as *const u8 as *const i8,
                        ) });
                        (unsafe { (*ctxt).error = XPATH_INVALID_OPERAND as i32 });
                        xmlXPathPopFrame(ctxt, frame);
                    } else {
                        i = 0 as i32;
                        while i < (unsafe { (*op).value }) {
                            if (unsafe { *((*ctxt).valueTab)
                                .offset(((*ctxt).valueNr - 1 as i32 - i) as isize) })
                            .is_null()
                            {
                                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                                    *__xmlGenericErrorContext(),
                                    b"xmlXPathCompOpEval: parameter error\n\0" as *const u8
                                        as *const i8,
                                ) });
                                (unsafe { (*ctxt).error = XPATH_INVALID_OPERAND as i32 });
                                xmlXPathPopFrame(ctxt, frame);
                                break;
                            } else {
                                i += 1;
                            }
                        }
                        if unsafe { ((*op).cache).is_some() } {
                            func = unsafe { (*op).cache };
                            current_block_226 = 14187386403465544025;
                        } else {
                            let mut URI_0: *const xmlChar = 0 as *const xmlChar;
                            if (unsafe { (*op).value5 }).is_null() {
                                func = xmlXPathFunctionLookup(
                                    unsafe { (*ctxt).context },
                                    (unsafe { (*op).value4 }) as *const xmlChar,
                                );
                                current_block_226 = 13718575627189773797;
                            } else {
                                URI_0 = xmlXPathNsLookup(
                                    unsafe { (*ctxt).context },
                                    (unsafe { (*op).value5 }) as *const xmlChar,
                                );
                                if URI_0.is_null() {
                                    (unsafe { (* __xmlGenericError ()) . expect ("non-null function pointer" ,) (* __xmlGenericErrorContext () , b"xmlXPathCompOpEval: function %s bound to undefined prefix %s\n\0" as * const u8 as * const i8 , (* op) . value4 as * mut i8 , (* op) . value5 as * mut i8 ,) }) ;
                                    xmlXPathPopFrame(ctxt, frame);
                                    (unsafe { (*ctxt).error = XPATH_UNDEF_PREFIX_ERROR as i32 });
                                    current_block_226 = 11940120049376251063;
                                } else {
                                    func = xmlXPathFunctionLookupNS(
                                        unsafe { (*ctxt).context },
                                        (unsafe { (*op).value4 }) as *const xmlChar,
                                        URI_0,
                                    );
                                    current_block_226 = 13718575627189773797;
                                }
                            }
                            match current_block_226 {
                                11940120049376251063 => {}
                                _ => {
                                    if func.is_none() {
                                        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                                            *__xmlGenericErrorContext(),
                                            b"xmlXPathCompOpEval: function %s not found\n\0"
                                                as *const u8
                                                as *const i8,
                                            (*op).value4 as *mut i8,
                                        ) });
                                        xmlXPathErr(ctxt, XPATH_UNKNOWN_FUNC_ERROR as i32);
                                        return 0 as i32;
                                    }
                                    let fresh352 = unsafe { &mut ((*op).cache) };
                                    *fresh352 = func;
                                    let fresh353 = unsafe { &mut ((*op).cacheURI) };
                                    *fresh353 = URI_0 as *mut libc::c_void;
                                    current_block_226 = 14187386403465544025;
                                }
                            }
                        }
                        match current_block_226 {
                            11940120049376251063 => {}
                            _ => {
                                oldFunc = unsafe { (*(*ctxt).context).function };
                                oldFuncURI = unsafe { (*(*ctxt).context).functionURI };
                                let fresh354 = unsafe { &mut ((*(*ctxt).context).function) };
                                *fresh354 = (unsafe { (*op).value4 }) as *const xmlChar;
                                let fresh355 = unsafe { &mut ((*(*ctxt).context).functionURI) };
                                *fresh355 = (unsafe { (*op).cacheURI }) as *const xmlChar;
                                (unsafe { func.expect("non-null function pointer")(ctxt, (*op).value) });
                                let fresh356 = unsafe { &mut ((*(*ctxt).context).function) };
                                *fresh356 = oldFunc;
                                let fresh357 = unsafe { &mut ((*(*ctxt).context).functionURI) };
                                *fresh357 = oldFuncURI;
                                if (unsafe { (*ctxt).error }) == XPATH_EXPRESSION_OK as i32
                                    && (unsafe { (*ctxt).valueNr }) != (unsafe { (*ctxt).valueFrame }) + 1 as i32
                                {
                                    xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
                                    return 0 as i32;
                                }
                                xmlXPathPopFrame(ctxt, frame);
                            }
                        }
                    }
                }
            }
        }
        14 => {
            if (unsafe { (*op).ch1 }) != -(1 as i32) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
                if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                    return 0 as i32;
                }
            }
            if (unsafe { (*op).ch2 }) != -(1 as i32) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) });
                if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                    return 0 as i32;
                }
            }
        }
        15 | 16 => {
            let mut set: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
            if (unsafe { (*op).ch1 }) != -(1 as i32)
                && (unsafe { (*op).ch2 }) != -(1 as i32)
                && ((unsafe { (*((*comp).steps).offset((*op).ch1 as isize)).op }) as u32
                    == XPATH_OP_SORT as i32 as u32
                    || (unsafe { (*((*comp).steps).offset((*op).ch1 as isize)).op }) as u32
                        == XPATH_OP_FILTER as i32 as u32)
                && (unsafe { (*((*comp).steps).offset((*op).ch2 as isize)).op }) as u32
                    == XPATH_OP_VALUE as i32 as u32
            {
                let mut val_0: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
                val_0 = (unsafe { (*((*comp).steps).offset((*op).ch2 as isize)).value4 }) as xmlXPathObjectPtr;
                if !val_0.is_null()
                    && (unsafe { (*val_0).type_0 }) as u32 == XPATH_NUMBER as i32 as u32
                    && (unsafe { (*val_0).floatval }) == 1.0f64
                {
                    let mut first: xmlNodePtr = 0 as xmlNodePtr;
                    total += xmlXPathCompOpEvalFirst(
                        ctxt,
                        unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) },
                        &mut first,
                    );
                    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                        return 0 as i32;
                    }
                    if !(unsafe { (*ctxt).value }).is_null()
                        && (unsafe { (*(*ctxt).value).type_0 }) as u32 == XPATH_NODESET as i32 as u32
                        && !(unsafe { (*(*ctxt).value).nodesetval }).is_null()
                        && (unsafe { (*(*(*ctxt).value).nodesetval).nodeNr }) > 1 as i32
                    {
                        xmlXPathNodeSetClearFromPos(
                            unsafe { (*(*ctxt).value).nodesetval },
                            1 as i32,
                            1 as i32,
                        );
                    }
                    current_block_226 = 11940120049376251063;
                } else {
                    current_block_226 = 2640716771647493481;
                }
            } else {
                current_block_226 = 2640716771647493481;
            }
            match current_block_226 {
                11940120049376251063 => {}
                _ => {
                    if (unsafe { (*op).ch1 }) != -(1 as i32)
                        && (unsafe { (*op).ch2 }) != -(1 as i32)
                        && (unsafe { (*((*comp).steps).offset((*op).ch1 as isize)).op }) as u32
                            == XPATH_OP_SORT as i32 as u32
                        && (unsafe { (*((*comp).steps).offset((*op).ch2 as isize)).op }) as u32
                            == XPATH_OP_SORT as i32 as u32
                    {
                        let mut f: i32 = unsafe { (*((*comp).steps).offset((*op).ch2 as isize)).ch1 };
                        if f != -(1 as i32)
                            && (unsafe { (*((*comp).steps).offset(f as isize)).op }) as u32
                                == XPATH_OP_FUNCTION as i32 as u32
                            && (unsafe { (*((*comp).steps).offset(f as isize)).value5 }).is_null()
                            && (unsafe { (*((*comp).steps).offset(f as isize)).value }) == 0 as i32
                            && !(unsafe { (*((*comp).steps).offset(f as isize)).value4 }).is_null()
                            && (unsafe { xmlStrEqual(
                                (*((*comp).steps).offset(f as isize)).value4 as *const xmlChar,
                                b"last\0" as *const u8 as *const i8 as *mut xmlChar,
                            ) }) != 0
                        {
                            let mut last: xmlNodePtr = 0 as xmlNodePtr;
                            total += xmlXPathCompOpEvalLast(
                                ctxt,
                                unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) },
                                &mut last,
                            );
                            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                                return 0 as i32;
                            }
                            if !(unsafe { (*ctxt).value }).is_null()
                                && (unsafe { (*(*ctxt).value).type_0 }) as u32 == XPATH_NODESET as i32 as u32
                                && !(unsafe { (*(*ctxt).value).nodesetval }).is_null()
                                && !(unsafe { (*(*(*ctxt).value).nodesetval).nodeTab }).is_null()
                                && (unsafe { (*(*(*ctxt).value).nodesetval).nodeNr }) > 1 as i32
                            {
                                xmlXPathNodeSetKeepLast(unsafe { (*(*ctxt).value).nodesetval });
                            }
                            current_block_226 = 11940120049376251063;
                        } else {
                            current_block_226 = 15696916892398440870;
                        }
                    } else {
                        current_block_226 = 15696916892398440870;
                    }
                    match current_block_226 {
                        11940120049376251063 => {}
                        _ => {
                            if (unsafe { (*op).ch1 }) != -(1 as i32) {
                                total += xmlXPathCompOpEval(
                                    ctxt,
                                    unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) },
                                );
                            }
                            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                                return 0 as i32;
                            }
                            if !((unsafe { (*op).ch2 }) == -(1 as i32)) {
                                if !(unsafe { (*ctxt).value }).is_null() {
                                    if (unsafe { (*ctxt).value }).is_null()
                                        || (unsafe { (*(*ctxt).value).type_0 }) as u32
                                            != XPATH_NODESET as i32 as u32
                                    {
                                        xmlXPathErr(ctxt, XPATH_INVALID_TYPE as i32);
                                        return 0 as i32;
                                    }
                                    set = unsafe { (*(*ctxt).value).nodesetval };
                                    if !set.is_null() {
                                        xmlXPathNodeSetFilter(
                                            ctxt,
                                            set,
                                            unsafe { (*op).ch2 },
                                            1 as i32,
                                            unsafe { (*set).nodeNr },
                                            1 as i32,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        17 => {
            if (unsafe { (*op).ch1 }) != -(1 as i32) {
                total += xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
            }
            if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                return 0 as i32;
            }
            if !(unsafe { (*ctxt).value }).is_null()
                && (unsafe { (*(*ctxt).value).type_0 }) as u32 == XPATH_NODESET as i32 as u32
                && !(unsafe { (*(*ctxt).value).nodesetval }).is_null()
                && (unsafe { (*(*(*ctxt).value).nodesetval).nodeNr }) > 1 as i32
            {
                xmlXPathNodeSetSort(unsafe { (*(*ctxt).value).nodesetval });
            }
        }
        _ => {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"XPath: unknown precompiled operation %d\n\0" as *const u8 as *const i8,
                (*op).op as u32,
            ) });
            (unsafe { (*ctxt).error = XPATH_INVALID_OPERAND as i32 });
        }
    }
    (unsafe { (*(*ctxt).context).depth -= 1 as i32 });
    return total;
}
extern "C" fn xmlXPathCompOpEvalToBoolean(
    mut ctxt: xmlXPathParserContextPtr,
    mut op: xmlXPathStepOpPtr,
    mut isPredicate: i32,
) -> i32 {
    let mut resObj: xmlXPathObjectPtr = 0 as xmlXPathObjectPtr;
    loop {
        if (unsafe { (*(*ctxt).context).opLimit }) != 0 as i32 as u64
            && xmlXPathCheckOpLimit(ctxt, 1 as i32 as u64) < 0 as i32
        {
            return 0 as i32;
        }
        match (unsafe { (*op).op }) as u32 {
            0 => return 0 as i32,
            11 => {
                resObj = (unsafe { (*op).value4 }) as xmlXPathObjectPtr;
                if isPredicate != 0 {
                    return xmlXPathEvaluatePredicateResult(ctxt, resObj);
                }
                return xmlXPathCastToBoolean(resObj);
            }
            17 => {
                if (unsafe { (*op).ch1 }) != -(1 as i32) {
                    op = (unsafe { &mut *((*(*ctxt).comp).steps).offset((*op).ch1 as isize) })
                        as *mut xmlXPathStepOp;
                } else {
                    return 0 as i32;
                }
            }
            10 => {
                if (unsafe { (*op).ch1 }) == -(1 as i32) {
                    return 0 as i32;
                }
                xmlXPathCompOpEval(
                    ctxt,
                    unsafe { &mut *((*(*ctxt).comp).steps).offset((*op).ch1 as isize) },
                );
                if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                    return -(1 as i32);
                }
                xmlXPathNodeCollectAndTest(
                    ctxt,
                    op,
                    0 as *mut xmlNodePtr,
                    0 as *mut xmlNodePtr,
                    1 as i32,
                );
                if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                    return -(1 as i32);
                }
                resObj = valuePop(ctxt);
                if resObj.is_null() {
                    return -(1 as i32);
                }
                break;
            }
            _ => {
                xmlXPathCompOpEval(ctxt, op);
                if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
                    return -(1 as i32);
                }
                resObj = valuePop(ctxt);
                if resObj.is_null() {
                    return -(1 as i32);
                }
                break;
            }
        }
    }
    if !resObj.is_null() {
        let mut res: i32 = 0;
        if (unsafe { (*resObj).type_0 }) as u32 == XPATH_BOOLEAN as i32 as u32 {
            res = unsafe { (*resObj).boolval };
        } else if isPredicate != 0 {
            res = xmlXPathEvaluatePredicateResult(ctxt, resObj);
        } else {
            res = xmlXPathCastToBoolean(resObj);
        }
        xmlXPathReleaseObject(unsafe { (*ctxt).context }, resObj);
        return res;
    }
    return 0 as i32;
}
extern "C" fn xmlXPathRunStreamEval(
    mut ctxt: xmlXPathContextPtr,
    mut comp: xmlPatternPtr,
    mut resultSeq: *mut xmlXPathObjectPtr,
    mut toBool: i32,
) -> i32 {
    let mut current_block: u64;
    let mut max_depth: i32 = 0;
    let mut min_depth: i32 = 0;
    let mut from_root: i32 = 0;
    let mut ret: i32 = 0;
    let mut depth: i32 = 0;
    let mut eval_all_nodes: i32 = 0;
    let mut cur: xmlNodePtr = 0 as xmlNodePtr;
    let mut limit: xmlNodePtr = 0 as xmlNodePtr;
    let mut patstream: xmlStreamCtxtPtr = 0 as xmlStreamCtxtPtr;
    let mut nb_nodes: i32 = 0 as i32;
    if ctxt.is_null() || comp.is_null() {
        return -(1 as i32);
    }
    max_depth = unsafe { xmlPatternMaxDepth(comp) };
    if max_depth == -(1 as i32) {
        return -(1 as i32);
    }
    if max_depth == -(2 as i32) {
        max_depth = 10000 as i32;
    }
    min_depth = unsafe { xmlPatternMinDepth(comp) };
    if min_depth == -(1 as i32) {
        return -(1 as i32);
    }
    from_root = unsafe { xmlPatternFromRoot(comp) };
    if from_root < 0 as i32 {
        return -(1 as i32);
    }
    if toBool == 0 {
        if resultSeq.is_null() {
            return -(1 as i32);
        }
        (unsafe { *resultSeq = xmlXPathCacheNewNodeSet(ctxt, 0 as xmlNodePtr) });
        if (unsafe { *resultSeq }).is_null() {
            return -(1 as i32);
        }
    }
    if min_depth == 0 as i32 {
        if from_root != 0 {
            if toBool != 0 {
                return 1 as i32;
            }
            xmlXPathNodeSetAddUnique(unsafe { (**resultSeq).nodesetval }, (unsafe { (*ctxt).doc }) as xmlNodePtr);
        } else {
            if toBool != 0 {
                return 1 as i32;
            }
            xmlXPathNodeSetAddUnique(unsafe { (**resultSeq).nodesetval }, unsafe { (*ctxt).node });
        }
    }
    if max_depth == 0 as i32 {
        return 0 as i32;
    }
    if from_root != 0 {
        cur = (unsafe { (*ctxt).doc }) as xmlNodePtr;
    } else if !(unsafe { (*ctxt).node }).is_null() {
        match (unsafe { (*(*ctxt).node).type_0 }) as u32 {
            1 | 9 | 11 | 13 => {
                cur = unsafe { (*ctxt).node };
            }
            2 | 3 | 4 | 5 | 6 | 7 | 8 | 12 | 14 | 10 | 15 | 16 | 17 | 18 | 19 | 20 | _ => {}
        }
        limit = cur;
    }
    if cur.is_null() {
        return 0 as i32;
    }
    patstream = unsafe { xmlPatternGetStreamCtxt(comp) };
    if patstream.is_null() {
        return 0 as i32;
    }
    eval_all_nodes = unsafe { xmlStreamWantsAnyNode(patstream) };
    if from_root != 0 {
        ret = unsafe { xmlStreamPush(patstream, 0 as *const xmlChar, 0 as *const xmlChar) };
        if ret < 0 as i32 {
            current_block = 17836213544692497527;
        } else if ret == 1 as i32 {
            if toBool != 0 {
                current_block = 15949864226568933613;
            } else {
                xmlXPathNodeSetAddUnique(unsafe { (**resultSeq).nodesetval }, cur);
                current_block = 17836213544692497527;
            }
        } else {
            current_block = 17836213544692497527;
        }
    } else {
        current_block = 17836213544692497527;
    }
    match current_block {
        17836213544692497527 => {
            depth = 0 as i32;
            'c_50591: loop {
                if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
                    current_block = 15901411630970032088;
                    break;
                }
                if !(unsafe { (*cur).children }).is_null() && depth < max_depth {
                    if (unsafe { (*(*cur).children).type_0 }) as u32 != XML_ENTITY_DECL as i32 as u32 {
                        cur = unsafe { (*cur).children };
                        depth += 1;
                        if (unsafe { (*cur).type_0 }) as u32 != XML_DTD_NODE as i32 as u32 {
                            current_block = 17075014677070940716;
                        } else {
                            current_block = 10301740260014665685;
                        }
                    } else {
                        current_block = 10301740260014665685;
                    }
                } else {
                    current_block = 10301740260014665685;
                }
                match current_block {
                    10301740260014665685 => {
                        if cur == limit {
                            current_block = 15901411630970032088;
                            break;
                        }
                        loop {
                            if (unsafe { (*cur).next }).is_null() {
                                current_block = 11865390570819897086;
                                break;
                            }
                            cur = unsafe { (*cur).next };
                            if (unsafe { (*cur).type_0 }) as u32 != XML_ENTITY_DECL as i32 as u32
                                && (unsafe { (*cur).type_0 }) as u32 != XML_DTD_NODE as i32 as u32
                            {
                                current_block = 12930649117290160518;
                                break;
                            }
                        }
                        match current_block {
                            12930649117290160518 => {}
                            _ => {
                                loop {
                                    cur = unsafe { (*cur).parent };
                                    depth -= 1;
                                    if cur.is_null()
                                        || cur == limit
                                        || (unsafe { (*cur).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
                                    {
                                        current_block = 15901411630970032088;
                                        break 'c_50591;
                                    }
                                    if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                                        ret = unsafe { xmlStreamPop(patstream) };
                                    } else if eval_all_nodes != 0
                                        && ((unsafe { (*cur).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
                                            || (unsafe { (*cur).type_0 }) as u32
                                                == XML_CDATA_SECTION_NODE as i32 as u32
                                            || (unsafe { (*cur).type_0 }) as u32
                                                == XML_COMMENT_NODE as i32 as u32
                                            || (unsafe { (*cur).type_0 }) as u32 == XML_PI_NODE as i32 as u32)
                                    {
                                        ret = unsafe { xmlStreamPop(patstream) };
                                    }
                                    if !(unsafe { (*cur).next }).is_null() {
                                        cur = unsafe { (*cur).next };
                                        break;
                                    } else if cur.is_null() {
                                        break;
                                    }
                                }
                                current_block = 17075014677070940716;
                            }
                        }
                    }
                    _ => {}
                }
                match current_block {
                    17075014677070940716 => {
                        if !(!cur.is_null() && depth >= 0 as i32) {
                            current_block = 15901411630970032088;
                            break;
                        }
                    }
                    _ => {}
                }
                's_315: loop {
                    if (unsafe { (*ctxt).opLimit }) != 0 as i32 as u64 {
                        if (unsafe { (*ctxt).opCount }) >= (unsafe { (*ctxt).opLimit }) {
                            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                                *__xmlGenericErrorContext(),
                                b"XPath operation limit exceeded\n\0" as *const u8 as *const i8,
                            ) });
                            (unsafe { xmlFreeStreamCtxt(patstream) });
                            return -(1 as i32);
                        }
                        let fresh358 = unsafe { &mut ((*ctxt).opCount) };
                        *fresh358 = (*fresh358).wrapping_add(1);
                    }
                    nb_nodes += 1;
                    match (unsafe { (*cur).type_0 }) as u32 {
                        1 | 3 | 4 | 8 | 7 => {}
                        _ => {
                            break;
                        }
                    }
                    if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                        ret = unsafe { xmlStreamPush(
                            patstream,
                            (*cur).name,
                            if !((*cur).ns).is_null() {
                                (*(*cur).ns).href
                            } else {
                                0 as *const xmlChar
                            },
                        ) };
                    } else {
                        if !(eval_all_nodes != 0) {
                            break;
                        }
                        ret = unsafe { xmlStreamPushNode(
                            patstream,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                            (*cur).type_0 as i32,
                        ) };
                    }
                    if !(ret < 0 as i32) {
                        if ret == 1 as i32 {
                            if toBool != 0 {
                                current_block = 15949864226568933613;
                                break 'c_50591;
                            }
                            if xmlXPathNodeSetAddUnique(unsafe { (**resultSeq).nodesetval }, cur) < 0 as i32 {
                                (unsafe { (*ctxt).lastError.domain = XML_FROM_XPATH as i32 });
                                (unsafe { (*ctxt).lastError.code = XML_ERR_NO_MEMORY as i32 });
                            }
                        }
                    }
                    if !((unsafe { (*cur).children }).is_null() || depth >= max_depth) {
                        break;
                    }
                    ret = unsafe { xmlStreamPop(patstream) };
                    loop {
                        if (unsafe { (*cur).next }).is_null() {
                            break 's_315;
                        }
                        cur = unsafe { (*cur).next };
                        if (unsafe { (*cur).type_0 }) as u32 != XML_ENTITY_DECL as i32 as u32
                            && (unsafe { (*cur).type_0 }) as u32 != XML_DTD_NODE as i32 as u32
                        {
                            break;
                        }
                    }
                }
            }
            match current_block {
                15949864226568933613 => {}
                _ => {
                    if !patstream.is_null() {
                        (unsafe { xmlFreeStreamCtxt(patstream) });
                    }
                    return 0 as i32;
                }
            }
        }
        _ => {}
    }
    if !patstream.is_null() {
        (unsafe { xmlFreeStreamCtxt(patstream) });
    }
    return 1 as i32;
}
extern "C" fn xmlXPathRunEval(mut ctxt: xmlXPathParserContextPtr, mut toBool: i32) -> i32 {
    let mut comp: xmlXPathCompExprPtr = 0 as *mut xmlXPathCompExpr;
    let mut oldDepth: i32 = 0;
    if ctxt.is_null() || (unsafe { (*ctxt).comp }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).valueTab }).is_null() {
        let fresh359 = unsafe { &mut ((*ctxt).valueTab) };
        *fresh359 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            (10 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlXPathObjectPtr>() as u64),
        ) }) as *mut xmlXPathObjectPtr;
        if (unsafe { (*ctxt).valueTab }).is_null() {
            xmlXPathPErrMemory(
                ctxt,
                b"creating evaluation context\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        (unsafe { (*ctxt).valueNr = 0 as i32 });
        (unsafe { (*ctxt).valueMax = 10 as i32 });
        let fresh360 = unsafe { &mut ((*ctxt).value) };
        *fresh360 = 0 as xmlXPathObjectPtr;
        (unsafe { (*ctxt).valueFrame = 0 as i32 });
    }
    if !(unsafe { (*(*ctxt).comp).stream }).is_null() {
        let mut res: i32 = 0;
        if toBool != 0 {
            res = xmlXPathRunStreamEval(
                unsafe { (*ctxt).context },
                unsafe { (*(*ctxt).comp).stream },
                0 as *mut xmlXPathObjectPtr,
                1 as i32,
            );
            if res != -(1 as i32) {
                return res;
            }
        } else {
            let mut resObj: xmlXPathObjectPtr = 0 as xmlXPathObjectPtr;
            res = xmlXPathRunStreamEval(
                unsafe { (*ctxt).context },
                unsafe { (*(*ctxt).comp).stream },
                &mut resObj,
                0 as i32,
            );
            if res != -(1 as i32) && !resObj.is_null() {
                valuePush(ctxt, resObj);
                return 0 as i32;
            }
            if !resObj.is_null() {
                xmlXPathReleaseObject(unsafe { (*ctxt).context }, resObj);
            }
        }
    }
    comp = unsafe { (*ctxt).comp };
    if (unsafe { (*comp).last }) < 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlXPathRunEval: last is less than zero\n\0" as *const u8 as *const i8,
        ) });
        return -(1 as i32);
    }
    oldDepth = unsafe { (*(*ctxt).context).depth };
    if toBool != 0 {
        return xmlXPathCompOpEvalToBoolean(
            ctxt,
            unsafe { &mut *((*comp).steps).offset((*comp).last as isize) },
            0 as i32,
        );
    } else {
        xmlXPathCompOpEval(ctxt, unsafe { &mut *((*comp).steps).offset((*comp).last as isize) });
    }
    (unsafe { (*(*ctxt).context).depth = oldDepth });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlXPathEvalPredicate(
    mut ctxt: xmlXPathContextPtr,
    mut res: xmlXPathObjectPtr,
) -> i32 {
    if ctxt.is_null() || res.is_null() {
        return 0 as i32;
    }
    match (unsafe { (*res).type_0 }) as u32 {
        2 => return unsafe { (*res).boolval },
        3 => {
            return ((unsafe { (*res).floatval }) == (unsafe { (*ctxt).proximityPosition }) as f64) as i32;
        }
        1 | 9 => {
            if (unsafe { (*res).nodesetval }).is_null() {
                return 0 as i32;
            }
            return ((unsafe { (*(*res).nodesetval).nodeNr }) != 0 as i32) as i32;
        }
        4 => {
            return (!(unsafe { (*res).stringval }).is_null() && (unsafe { xmlStrlen((*res).stringval) }) != 0 as i32)
                as i32;
        }
        _ => {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"Internal error at %s:%d\n\0" as *const u8 as *const i8,
                b"xpath.c\0" as *const u8 as *const i8,
                13995 as i32,
            ) });
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlXPathEvaluatePredicateResult(
    mut ctxt: xmlXPathParserContextPtr,
    mut res: xmlXPathObjectPtr,
) -> i32 {
    if ctxt.is_null() || res.is_null() {
        return 0 as i32;
    }
    match (unsafe { (*res).type_0 }) as u32 {
        2 => return unsafe { (*res).boolval },
        3 => {
            return ((unsafe { (*res).floatval }) == (unsafe { (*(*ctxt).context).proximityPosition }) as f64) as i32;
        }
        1 | 9 => {
            if (unsafe { (*res).nodesetval }).is_null() {
                return 0 as i32;
            }
            return ((unsafe { (*(*res).nodesetval).nodeNr }) != 0 as i32) as i32;
        }
        4 => {
            return (!(unsafe { (*res).stringval }).is_null()
                && (unsafe { *((*res).stringval).offset(0 as i32 as isize) }) as i32 != 0 as i32)
                as i32;
        }
        _ => {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"Internal error at %s:%d\n\0" as *const u8 as *const i8,
                b"xpath.c\0" as *const u8 as *const i8,
                14046 as i32,
            ) });
        }
    }
    return 0 as i32;
}
extern "C" fn xmlXPathTryStreamCompile(
    mut ctxt: xmlXPathContextPtr,
    mut str: *const xmlChar,
) -> xmlXPathCompExprPtr {
    let mut stream: xmlPatternPtr = 0 as *mut xmlPattern;
    let mut comp: xmlXPathCompExprPtr = 0 as *mut xmlXPathCompExpr;
    let mut dict: xmlDictPtr = 0 as xmlDictPtr;
    let mut namespaces: *mut *const xmlChar = 0 as *mut *const xmlChar;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    if (unsafe { xmlStrchr(str, '[' as i32 as xmlChar) }).is_null()
        && (unsafe { xmlStrchr(str, '(' as i32 as xmlChar) }).is_null()
        && (unsafe { xmlStrchr(str, '@' as i32 as xmlChar) }).is_null()
    {
        let mut tmp: *const xmlChar = 0 as *const xmlChar;
        tmp = unsafe { xmlStrchr(str, ':' as i32 as xmlChar) };
        if !tmp.is_null()
            && (ctxt.is_null()
                || (unsafe { (*ctxt).nsNr }) == 0 as i32
                || (unsafe { *tmp.offset(1 as i32 as isize) }) as i32 == ':' as i32)
        {
            return 0 as xmlXPathCompExprPtr;
        }
        if !ctxt.is_null() {
            dict = unsafe { (*ctxt).dict };
            if (unsafe { (*ctxt).nsNr }) > 0 as i32 {
                namespaces = (unsafe { xmlMalloc.expect("non-null function pointer")(
                    ((2 as i32 * ((*ctxt).nsNr + 1 as i32)) as u64)
                        .wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
                ) }) as *mut *const xmlChar;
                if namespaces.is_null() {
                    xmlXPathErrMemory(
                        ctxt,
                        b"allocating namespaces array\n\0" as *const u8 as *const i8,
                    );
                    return 0 as xmlXPathCompExprPtr;
                }
                i = 0 as i32;
                j = 0 as i32;
                while j < (unsafe { (*ctxt).nsNr }) {
                    ns = unsafe { *((*ctxt).namespaces).offset(j as isize) };
                    let fresh361 = i;
                    i = i + 1;
                    let fresh362 = unsafe { &mut (*namespaces.offset(fresh361 as isize)) };
                    *fresh362 = unsafe { (*ns).href };
                    let fresh363 = i;
                    i = i + 1;
                    let fresh364 = unsafe { &mut (*namespaces.offset(fresh363 as isize)) };
                    *fresh364 = unsafe { (*ns).prefix };
                    j += 1;
                }
                let fresh365 = i;
                i = i + 1;
                let fresh366 = unsafe { &mut (*namespaces.offset(fresh365 as isize)) };
                *fresh366 = 0 as *const xmlChar;
                let fresh367 = unsafe { &mut (*namespaces.offset(i as isize)) };
                *fresh367 = 0 as *const xmlChar;
            }
        }
        stream = unsafe { xmlPatterncompile(str, dict, XML_PATTERN_XPATH as i32, namespaces) };
        if !namespaces.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(
                namespaces as *mut *mut xmlChar as *mut libc::c_void,
            ) });
        }
        if !stream.is_null() && (unsafe { xmlPatternStreamable(stream) }) == 1 as i32 {
            comp = xmlXPathNewCompExpr();
            if comp.is_null() {
                xmlXPathErrMemory(
                    ctxt,
                    b"allocating streamable expression\n\0" as *const u8 as *const i8,
                );
                return 0 as xmlXPathCompExprPtr;
            }
            let fresh368 = unsafe { &mut ((*comp).stream) };
            *fresh368 = stream;
            let fresh369 = unsafe { &mut ((*comp).dict) };
            *fresh369 = dict;
            if !(unsafe { (*comp).dict }).is_null() {
                (unsafe { xmlDictReference((*comp).dict) });
            }
            return comp;
        }
        (unsafe { xmlFreePattern(stream) });
    }
    return 0 as xmlXPathCompExprPtr;
}
extern "C" fn xmlXPathOptimizeExpression(
    mut pctxt: xmlXPathParserContextPtr,
    mut op: xmlXPathStepOpPtr,
) {
    let mut comp: xmlXPathCompExprPtr = unsafe { (*pctxt).comp };
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    if (unsafe { (*op).op }) as u32 == XPATH_OP_COLLECT as i32 as u32
        && (unsafe { (*op).ch1 }) != -(1 as i32)
        && (unsafe { (*op).ch2 }) == -(1 as i32)
    {
        let mut prevop: xmlXPathStepOpPtr =
            (unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) }) as *mut xmlXPathStepOp;
        if (unsafe { (*prevop).op }) as u32 == XPATH_OP_COLLECT as i32 as u32
            && (unsafe { (*prevop).value }) as xmlXPathAxisVal as u32 == AXIS_DESCENDANT_OR_SELF as i32 as u32
            && (unsafe { (*prevop).ch2 }) == -(1 as i32)
            && (unsafe { (*prevop).value2 }) as xmlXPathTestVal as u32 == NODE_TEST_TYPE as i32 as u32
            && (unsafe { (*prevop).value3 }) as xmlXPathTypeVal as u32 == NODE_TYPE_NODE as i32 as u32
        {
            match (unsafe { (*op).value }) as xmlXPathAxisVal as u32 {
                4 | 5 => {
                    (unsafe { (*op).ch1 = (*prevop).ch1 });
                    (unsafe { (*op).value = AXIS_DESCENDANT as i32 });
                }
                13 | 6 => {
                    (unsafe { (*op).ch1 = (*prevop).ch1 });
                    (unsafe { (*op).value = AXIS_DESCENDANT_OR_SELF as i32 });
                }
                _ => {}
            }
        }
    }
    if (unsafe { (*op).op }) as u32 == XPATH_OP_VALUE as i32 as u32 {
        return;
    }
    ctxt = unsafe { (*pctxt).context };
    if !ctxt.is_null() {
        if (unsafe { (*ctxt).depth }) >= 5000 as i32 {
            return;
        }
        (unsafe { (*ctxt).depth += 1 as i32 });
    }
    if (unsafe { (*op).ch1 }) != -(1 as i32) {
        xmlXPathOptimizeExpression(pctxt, unsafe { &mut *((*comp).steps).offset((*op).ch1 as isize) });
    }
    if (unsafe { (*op).ch2 }) != -(1 as i32) {
        xmlXPathOptimizeExpression(pctxt, unsafe { &mut *((*comp).steps).offset((*op).ch2 as isize) });
    }
    if !ctxt.is_null() {
        (unsafe { (*ctxt).depth -= 1 as i32 });
    }
}
#[no_mangle]
pub extern "C" fn xmlXPathCtxtCompile(
    mut ctxt: xmlXPathContextPtr,
    mut str: *const xmlChar,
) -> xmlXPathCompExprPtr {
    let mut pctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut comp: xmlXPathCompExprPtr = 0 as *mut xmlXPathCompExpr;
    let mut oldDepth: i32 = 0 as i32;
    comp = xmlXPathTryStreamCompile(ctxt, str);
    if !comp.is_null() {
        return comp;
    }
    (unsafe { xmlInitParser() });
    pctxt = xmlXPathNewParserContext(str, ctxt);
    if pctxt.is_null() {
        return 0 as xmlXPathCompExprPtr;
    }
    if !ctxt.is_null() {
        oldDepth = unsafe { (*ctxt).depth };
    }
    xmlXPathCompileExpr(pctxt, 1 as i32);
    if !ctxt.is_null() {
        (unsafe { (*ctxt).depth = oldDepth });
    }
    if (unsafe { (*pctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        xmlXPathFreeParserContext(pctxt);
        return 0 as xmlXPathCompExprPtr;
    }
    if (unsafe { *(*pctxt).cur }) as i32 != 0 as i32 {
        xmlXPatherror(
            pctxt,
            b"xpath.c\0" as *const u8 as *const i8,
            14254 as i32,
            XPATH_EXPR_ERROR as i32,
        );
        comp = 0 as xmlXPathCompExprPtr;
    } else {
        comp = unsafe { (*pctxt).comp };
        if (unsafe { (*comp).nbStep }) > 1 as i32 && (unsafe { (*comp).last }) >= 0 as i32 {
            if !ctxt.is_null() {
                oldDepth = unsafe { (*ctxt).depth };
            }
            xmlXPathOptimizeExpression(pctxt, unsafe { &mut *((*comp).steps).offset((*comp).last as isize) });
            if !ctxt.is_null() {
                (unsafe { (*ctxt).depth = oldDepth });
            }
        }
        let fresh370 = unsafe { &mut ((*pctxt).comp) };
        *fresh370 = 0 as xmlXPathCompExprPtr;
    }
    xmlXPathFreeParserContext(pctxt);
    if !comp.is_null() {
        let fresh371 = unsafe { &mut ((*comp).expr) };
        *fresh371 = unsafe { xmlStrdup(str) };
    }
    return comp;
}
#[no_mangle]
pub extern "C" fn xmlXPathCompile(mut str: *const xmlChar) -> xmlXPathCompExprPtr {
    return xmlXPathCtxtCompile(0 as xmlXPathContextPtr, str);
}
extern "C" fn xmlXPathCompiledEvalInternal(
    mut comp: xmlXPathCompExprPtr,
    mut ctxt: xmlXPathContextPtr,
    mut resObjPtr: *mut xmlXPathObjectPtr,
    mut toBool: i32,
) -> i32 {
    let mut pctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut resObj: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut res: i32 = 0;
    if ctxt.is_null() {
        (unsafe { __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_XPATH as i32,
            XML_ERR_INTERNAL_ERROR as i32,
            XML_ERR_FATAL,
            b"xpath.c\0" as *const u8 as *const i8,
            14319 as i32,
            0 as *const i8,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"NULL context pointer\n\0" as *const u8 as *const i8,
        ) });
        return -(1 as i32);
    }
    if comp.is_null() {
        return -(1 as i32);
    }
    (unsafe { xmlInitParser() });
    pctxt = xmlXPathCompParserContext(comp, ctxt);
    res = xmlXPathRunEval(pctxt, toBool);
    if (unsafe { (*pctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        resObj = 0 as xmlXPathObjectPtr;
    } else {
        resObj = valuePop(pctxt);
        if resObj.is_null() {
            if toBool == 0 {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"xmlXPathCompiledEval: No result on the stack.\n\0" as *const u8 as *const i8,
                ) });
            }
        } else if (unsafe { (*pctxt).valueNr }) > 0 as i32 {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlXPathCompiledEval: %d object(s) left on the stack.\n\0" as *const u8
                    as *const i8,
                (*pctxt).valueNr,
            ) });
        }
    }
    if !resObjPtr.is_null() {
        (unsafe { *resObjPtr = resObj });
    } else {
        xmlXPathReleaseObject(ctxt, resObj);
    }
    let fresh372 = unsafe { &mut ((*pctxt).comp) };
    *fresh372 = 0 as xmlXPathCompExprPtr;
    xmlXPathFreeParserContext(pctxt);
    return res;
}
#[no_mangle]
pub extern "C" fn xmlXPathCompiledEval(
    mut comp: xmlXPathCompExprPtr,
    mut ctx: xmlXPathContextPtr,
) -> xmlXPathObjectPtr {
    let mut res: xmlXPathObjectPtr = 0 as xmlXPathObjectPtr;
    xmlXPathCompiledEvalInternal(comp, ctx, &mut res, 0 as i32);
    return res;
}
#[no_mangle]
pub extern "C" fn xmlXPathCompiledEvalToBoolean(
    mut comp: xmlXPathCompExprPtr,
    mut ctxt: xmlXPathContextPtr,
) -> i32 {
    return xmlXPathCompiledEvalInternal(comp, ctxt, 0 as *mut xmlXPathObjectPtr, 1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlXPathEvalExpr(mut ctxt: xmlXPathParserContextPtr) {
    let mut comp: xmlXPathCompExprPtr = 0 as *mut xmlXPathCompExpr;
    let mut oldDepth: i32 = 0 as i32;
    if ctxt.is_null() {
        return;
    }
    comp = xmlXPathTryStreamCompile(unsafe { (*ctxt).context }, unsafe { (*ctxt).base });
    if !comp.is_null() {
        if !(unsafe { (*ctxt).comp }).is_null() {
            xmlXPathFreeCompExpr(unsafe { (*ctxt).comp });
        }
        let fresh373 = unsafe { &mut ((*ctxt).comp) };
        *fresh373 = comp;
    } else {
        if !(unsafe { (*ctxt).context }).is_null() {
            oldDepth = unsafe { (*(*ctxt).context).depth };
        }
        xmlXPathCompileExpr(ctxt, 1 as i32);
        if !(unsafe { (*ctxt).context }).is_null() {
            (unsafe { (*(*ctxt).context).depth = oldDepth });
        }
        if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
            return;
        }
        if (unsafe { *(*ctxt).cur }) as i32 != 0 as i32 {
            xmlXPathErr(ctxt, XPATH_EXPR_ERROR as i32);
            return;
        }
        if (unsafe { (*(*ctxt).comp).nbStep }) > 1 as i32 && (unsafe { (*(*ctxt).comp).last }) >= 0 as i32 {
            if !(unsafe { (*ctxt).context }).is_null() {
                oldDepth = unsafe { (*(*ctxt).context).depth };
            }
            xmlXPathOptimizeExpression(
                ctxt,
                unsafe { &mut *((*(*ctxt).comp).steps).offset((*(*ctxt).comp).last as isize) },
            );
            if !(unsafe { (*ctxt).context }).is_null() {
                (unsafe { (*(*ctxt).context).depth = oldDepth });
            }
        }
    }
    xmlXPathRunEval(ctxt, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlXPathEval(
    mut str: *const xmlChar,
    mut ctx: xmlXPathContextPtr,
) -> xmlXPathObjectPtr {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut res: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if ctx.is_null() {
        (unsafe { __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_XPATH as i32,
            XML_ERR_INTERNAL_ERROR as i32,
            XML_ERR_FATAL,
            b"xpath.c\0" as *const u8 as *const i8,
            14471 as i32,
            0 as *const i8,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"NULL context pointer\n\0" as *const u8 as *const i8,
        ) });
        return 0 as xmlXPathObjectPtr;
    }
    (unsafe { xmlInitParser() });
    ctxt = xmlXPathNewParserContext(str, ctx);
    if ctxt.is_null() {
        return 0 as xmlXPathObjectPtr;
    }
    xmlXPathEvalExpr(ctxt);
    if (unsafe { (*ctxt).error }) != XPATH_EXPRESSION_OK as i32 {
        res = 0 as xmlXPathObjectPtr;
    } else {
        res = valuePop(ctxt);
        if res.is_null() {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlXPathCompiledEval: No result on the stack.\n\0" as *const u8 as *const i8,
            ) });
        } else if (unsafe { (*ctxt).valueNr }) > 0 as i32 {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlXPathCompiledEval: %d object(s) left on the stack.\n\0" as *const u8
                    as *const i8,
                (*ctxt).valueNr,
            ) });
        }
    }
    xmlXPathFreeParserContext(ctxt);
    return res;
}
#[no_mangle]
pub extern "C" fn xmlXPathSetContextNode(mut node: xmlNodePtr, mut ctx: xmlXPathContextPtr) -> i32 {
    if node.is_null() || ctx.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*node).doc }) == (unsafe { (*ctx).doc }) {
        let fresh374 = unsafe { &mut ((*ctx).node) };
        *fresh374 = node;
        return 0 as i32;
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlXPathNodeEval(
    mut node: xmlNodePtr,
    mut str: *const xmlChar,
    mut ctx: xmlXPathContextPtr,
) -> xmlXPathObjectPtr {
    if str.is_null() {
        return 0 as xmlXPathObjectPtr;
    }
    if xmlXPathSetContextNode(node, ctx) < 0 as i32 {
        return 0 as xmlXPathObjectPtr;
    }
    return xmlXPathEval(str, ctx);
}
#[no_mangle]
pub extern "C" fn xmlXPathEvalExpression(
    mut str: *const xmlChar,
    mut ctxt: xmlXPathContextPtr,
) -> xmlXPathObjectPtr {
    return xmlXPathEval(str, ctxt);
}
extern "C" fn xmlXPathEscapeUriFunction(mut ctxt: xmlXPathParserContextPtr, mut nargs: i32) {
    let mut str: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut escape_reserved: i32 = 0;
    let mut target: xmlBufPtr = 0 as *mut xmlBuf;
    let mut cptr: *mut xmlChar = 0 as *mut xmlChar;
    let mut escape: [xmlChar; 4] = [0; 4];
    if ctxt.is_null() {
        return;
    }
    if nargs != 2 as i32 {
        xmlXPathErr(ctxt, XPATH_INVALID_ARITY as i32);
        return;
    }
    if (unsafe { (*ctxt).valueNr }) < (unsafe { (*ctxt).valueFrame }) + 2 as i32 {
        xmlXPathErr(ctxt, XPATH_STACK_ERROR as i32);
        return;
    }
    escape_reserved = xmlXPathPopBoolean(ctxt);
    if !(unsafe { (*ctxt).value }).is_null() && (unsafe { (*(*ctxt).value).type_0 }) as u32 != XPATH_STRING as i32 as u32 {
        xmlXPathStringFunction(ctxt, 1 as i32);
    }
    str = valuePop(ctxt);
    target = unsafe { xmlBufCreate() };
    escape[0 as i32 as usize] = '%' as i32 as xmlChar;
    escape[3 as i32 as usize] = 0 as i32 as xmlChar;
    if !target.is_null() {
        cptr = unsafe { (*str).stringval };
        while (unsafe { *cptr }) != 0 {
            if (unsafe { *cptr }) as i32 >= 'A' as i32 && (unsafe { *cptr }) as i32 <= 'Z' as i32
                || (unsafe { *cptr }) as i32 >= 'a' as i32 && (unsafe { *cptr }) as i32 <= 'z' as i32
                || (unsafe { *cptr }) as i32 >= '0' as i32 && (unsafe { *cptr }) as i32 <= '9' as i32
                || (unsafe { *cptr }) as i32 == '-' as i32
                || (unsafe { *cptr }) as i32 == '_' as i32
                || (unsafe { *cptr }) as i32 == '.' as i32
                || (unsafe { *cptr }) as i32 == '!' as i32
                || (unsafe { *cptr }) as i32 == '~' as i32
                || (unsafe { *cptr }) as i32 == '*' as i32
                || (unsafe { *cptr }) as i32 == '\'' as i32
                || (unsafe { *cptr }) as i32 == '(' as i32
                || (unsafe { *cptr }) as i32 == ')' as i32
                || (unsafe { *cptr }) as i32 == '%' as i32
                    && ((unsafe { *cptr.offset(1 as i32 as isize) }) as i32 >= 'A' as i32
                        && (unsafe { *cptr.offset(1 as i32 as isize) }) as i32 <= 'F' as i32
                        || (unsafe { *cptr.offset(1 as i32 as isize) }) as i32 >= 'a' as i32
                            && (unsafe { *cptr.offset(1 as i32 as isize) }) as i32 <= 'f' as i32
                        || (unsafe { *cptr.offset(1 as i32 as isize) }) as i32 >= '0' as i32
                            && (unsafe { *cptr.offset(1 as i32 as isize) }) as i32 <= '9' as i32)
                    && ((unsafe { *cptr.offset(2 as i32 as isize) }) as i32 >= 'A' as i32
                        && (unsafe { *cptr.offset(2 as i32 as isize) }) as i32 <= 'F' as i32
                        || (unsafe { *cptr.offset(2 as i32 as isize) }) as i32 >= 'a' as i32
                            && (unsafe { *cptr.offset(2 as i32 as isize) }) as i32 <= 'f' as i32
                        || (unsafe { *cptr.offset(2 as i32 as isize) }) as i32 >= '0' as i32
                            && (unsafe { *cptr.offset(2 as i32 as isize) }) as i32 <= '9' as i32)
                || escape_reserved == 0
                    && ((unsafe { *cptr }) as i32 == ';' as i32
                        || (unsafe { *cptr }) as i32 == '/' as i32
                        || (unsafe { *cptr }) as i32 == '?' as i32
                        || (unsafe { *cptr }) as i32 == ':' as i32
                        || (unsafe { *cptr }) as i32 == '@' as i32
                        || (unsafe { *cptr }) as i32 == '&' as i32
                        || (unsafe { *cptr }) as i32 == '=' as i32
                        || (unsafe { *cptr }) as i32 == '+' as i32
                        || (unsafe { *cptr }) as i32 == '$' as i32
                        || (unsafe { *cptr }) as i32 == ',' as i32)
            {
                (unsafe { xmlBufAdd(target, cptr, 1 as i32) });
            } else {
                if ((unsafe { *cptr }) as i32 >> 4 as i32) < 10 as i32 {
                    escape[1 as i32 as usize] =
                        ('0' as i32 + ((unsafe { *cptr }) as i32 >> 4 as i32)) as xmlChar;
                } else {
                    escape[1 as i32 as usize] =
                        ('A' as i32 - 10 as i32 + ((unsafe { *cptr }) as i32 >> 4 as i32)) as xmlChar;
                }
                if ((unsafe { *cptr }) as i32 & 0xf as i32) < 10 as i32 {
                    escape[2 as i32 as usize] =
                        ('0' as i32 + ((unsafe { *cptr }) as i32 & 0xf as i32)) as xmlChar;
                } else {
                    escape[2 as i32 as usize] =
                        ('A' as i32 - 10 as i32 + ((unsafe { *cptr }) as i32 & 0xf as i32)) as xmlChar;
                }
                (unsafe { xmlBufAdd(
                    target,
                    &mut *escape.as_mut_ptr().offset(0 as i32 as isize),
                    3 as i32,
                ) });
            }
            cptr = unsafe { cptr.offset(1) };
        }
    }
    valuePush(
        ctxt,
        xmlXPathCacheNewString(unsafe { (*ctxt).context }, unsafe { xmlBufContent(target as *const xmlBuf) }),
    );
    (unsafe { xmlBufFree(target) });
    xmlXPathReleaseObject(unsafe { (*ctxt).context }, str);
}
#[no_mangle]
pub extern "C" fn xmlXPathRegisterAllFunctions(mut ctxt: xmlXPathContextPtr) {
    xmlXPathRegisterFunc(
        ctxt,
        b"boolean\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathBooleanFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"ceiling\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathCeilingFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"count\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathCountFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"concat\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathConcatFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"contains\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathContainsFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"id\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathIdFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"false\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathFalseFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"floor\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathFloorFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"last\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathLastFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"lang\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathLangFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"local-name\0" as *const u8 as *const i8 as *const xmlChar,
        Some(
            xmlXPathLocalNameFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> (),
        ),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"not\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathNotFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"name\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathNameFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"namespace-uri\0" as *const u8 as *const i8 as *const xmlChar,
        Some(
            xmlXPathNamespaceURIFunction
                as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> (),
        ),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"normalize-space\0" as *const u8 as *const i8 as *const xmlChar,
        Some(
            xmlXPathNormalizeFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> (),
        ),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"number\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathNumberFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"position\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathPositionFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"round\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathRoundFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"string\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathStringFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"string-length\0" as *const u8 as *const i8 as *const xmlChar,
        Some(
            xmlXPathStringLengthFunction
                as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> (),
        ),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"starts-with\0" as *const u8 as *const i8 as *const xmlChar,
        Some(
            xmlXPathStartsWithFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> (),
        ),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"substring\0" as *const u8 as *const i8 as *const xmlChar,
        Some(
            xmlXPathSubstringFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> (),
        ),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"substring-before\0" as *const u8 as *const i8 as *const xmlChar,
        Some(
            xmlXPathSubstringBeforeFunction
                as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> (),
        ),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"substring-after\0" as *const u8 as *const i8 as *const xmlChar,
        Some(
            xmlXPathSubstringAfterFunction
                as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> (),
        ),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"sum\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathSumFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"true\0" as *const u8 as *const i8 as *const xmlChar,
        Some(xmlXPathTrueFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()),
    );
    xmlXPathRegisterFunc(
        ctxt,
        b"translate\0" as *const u8 as *const i8 as *const xmlChar,
        Some(
            xmlXPathTranslateFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> (),
        ),
    );
    xmlXPathRegisterFuncNS(
        ctxt,
        b"escape-uri\0" as *const u8 as *const i8 as *const xmlChar,
        b"http://www.w3.org/2002/08/xquery-functions\0" as *const u8 as *const i8 as *const xmlChar,
        Some(
            xmlXPathEscapeUriFunction as unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> (),
        ),
    );
}
