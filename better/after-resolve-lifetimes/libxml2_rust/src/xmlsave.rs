use ::libc;
extern "C" {
    
    pub type _IO_codecvt;
    
    
    
    pub type _xmlHashTable;
    
    
    
    
    
    
    fn memset(
        _: * mut core::ffi::c_void,
        _: i32,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn xmlBufContent(buf: * const crate::src::xmlstring::_xmlBuf) -> * mut u8;
    fn xmlBufUse(buf: * mut crate::src::xmlstring::_xmlBuf) -> u64;
    
    
    
    
    
    
    fn __xmlSimpleError(
        domain: i32,
        code: i32,
        node: * mut crate::src::threads::_xmlNode,
        msg: * const i8,
        extra: * const i8,
    );
    
    
    fn xmlCharEncCloseFunc(handler: * mut crate::src::threads::_xmlCharEncodingHandler) -> i32;
    
    
    fn __xmlIndentTreeOutput() -> * mut i32;
    
    fn xmlDumpEntityDecl(buf: * mut crate::src::tree::_xmlBuffer, ent: * mut crate::src::threads::_xmlEntity);
    
    
    
    static mut xmlFree: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
    fn __xmlGenericErrorContext() -> * mut * mut core::ffi::c_void;
    fn __xmlGenericError() -> * mut Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
    fn xmlFindCharEncodingHandler(
        name: * const i8,
    ) -> * mut crate::src::threads::_xmlCharEncodingHandler;
    fn xmlParseCharEncoding(name: * const i8) -> i32;
    fn xmlInitParser();
    fn __xmlSaveNoEmptyTags() -> * mut i32;
    fn __xmlTreeIndentString() -> * mut * const i8;
    
    
    
    
    static mut xmlMalloc: Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>;
    
    
    
    
    
    fn htmlGetMetaEncoding(doc: * mut crate::src::threads::_xmlDoc) -> * const u8;
    fn htmlSetMetaEncoding(doc: * mut crate::src::threads::_xmlDoc, encoding: * const u8) -> i32;
    fn htmlNodeDumpFormatOutput(
        buf: * mut crate::src::threads::_xmlOutputBuffer,
        doc: * mut crate::src::threads::_xmlDoc,
        cur: * mut crate::src::threads::_xmlNode,
        encoding: * const i8,
        format: i32,
    );
    fn htmlDocContentDumpFormatOutput(
        buf: * mut crate::src::threads::_xmlOutputBuffer,
        cur: * mut crate::src::threads::_xmlDoc,
        encoding: * const i8,
        format: i32,
    );
    fn htmlNodeDumpOutput(
        buf: * mut crate::src::threads::_xmlOutputBuffer,
        doc: * mut crate::src::threads::_xmlDoc,
        cur: * mut crate::src::threads::_xmlNode,
        encoding: * const i8,
    );
    fn htmlIsBooleanAttr(name: * const u8) -> i32;
    fn xmlBufCreate() -> * mut crate::src::xmlstring::_xmlBuf;
    fn xmlBufSetAllocationScheme(
        buf: * mut crate::src::xmlstring::_xmlBuf,
        scheme: u32,
    ) -> i32;
    fn xmlBufGetAllocationScheme(buf: * mut crate::src::xmlstring::_xmlBuf) -> i32;
    fn xmlBufFree(buf: * mut crate::src::xmlstring::_xmlBuf);
    fn xmlBufAdd(buf: * mut crate::src::xmlstring::_xmlBuf, str: * const u8, len: i32) -> i32;
    fn xmlBufWriteQuotedString(buf: * mut crate::src::xmlstring::_xmlBuf, string: * const u8) -> i32;
    fn xmlBufFromBuffer(buffer: * mut crate::src::tree::_xmlBuffer) -> * mut crate::src::xmlstring::_xmlBuf;
    fn xmlBufBackToBuffer(buf: * mut crate::src::xmlstring::_xmlBuf) -> * mut crate::src::tree::_xmlBuffer;
    fn xmlBufMergeBuffer(buf: * mut crate::src::xmlstring::_xmlBuf, buffer: * mut crate::src::tree::_xmlBuffer) -> i32;
    fn xmlCharEncOutput(output: * mut crate::src::threads::_xmlOutputBuffer, init: i32) -> i32;
}
pub use crate::src::tree::xmlBufferCreate;
pub use crate::src::tree::xmlBufferSetAllocationScheme;
pub use crate::src::tree::xmlFreeNode;
pub use crate::src::tree::xmlGetCompressMode;
pub use crate::src::tree::xmlGetIntSubset;
pub use crate::src::tree::xmlGetProp;
pub use crate::src::tree::xmlNewDocText;
pub use crate::src::valid::xmlDumpAttributeDecl;
pub use crate::src::valid::xmlDumpElementDecl;
pub use crate::src::valid::xmlDumpNotationTable;
pub use crate::src::xmlIO::xmlAllocOutputBuffer;
pub use crate::src::xmlIO::xmlOutputBufferClose;
pub use crate::src::xmlIO::xmlOutputBufferCreateBuffer;
pub use crate::src::xmlIO::xmlOutputBufferCreateFd;
pub use crate::src::xmlIO::xmlOutputBufferCreateFile;
pub use crate::src::xmlIO::xmlOutputBufferCreateFilename;
pub use crate::src::xmlIO::xmlOutputBufferCreateIO;
pub use crate::src::xmlIO::xmlOutputBufferFlush;
pub use crate::src::xmlIO::xmlOutputBufferWrite;
pub use crate::src::xmlIO::xmlOutputBufferWriteEscape;
pub use crate::src::xmlIO::xmlOutputBufferWriteString;
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrcasecmp;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrlen;
pub use crate::src::xmlstring::xmlStrndup;
pub use crate::src::xmlregexp::_xmlRegexp;
pub use crate::src::tree::xmlStringText;
pub use crate::src::tree::xmlStringTextNoenc;
pub use crate::src::xmllint::_IO_marker;
pub use crate::src::xmlmemory::_IO_wide_data;
pub use crate::src::xmlstring::_xmlBuf;
pub use crate::src::xpointer::_xmlDict;
pub type xmlChar = u8;
pub type size_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::tree::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::tree::_IO_FILE;
pub type xmlFreeFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>;
pub type xmlBufPtr = * mut crate::src::xmlstring::_xmlBuf;
pub type xmlBuf = crate::src::xmlstring::_xmlBuf;
pub type xmlCharEncodingHandlerPtr = * mut crate::src::threads::_xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = crate::src::threads::_xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub type _xmlCharEncodingHandler = crate::src::threads::_xmlCharEncodingHandler;
pub type iconv_t = * mut core::ffi::c_void;
pub type xmlCharEncodingOutputFunc = Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>;
pub type xmlCharEncodingInputFunc = Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>;
// #[derive(Copy, Clone)]

pub type _xmlOutputBuffer = crate::src::threads::_xmlOutputBuffer;
pub type xmlOutputCloseCallback = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type xmlOutputWriteCallback = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,_: i32,) -> i32>;
pub type xmlOutputBuffer = crate::src::threads::_xmlOutputBuffer;
pub type xmlOutputBufferPtr = * mut crate::src::threads::_xmlOutputBuffer;
// #[derive(Copy, Clone)]

pub type _xmlNode = crate::src::threads::_xmlNode;
pub type xmlNs = crate::src::threads::_xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlNs = crate::src::threads::_xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlDoc = crate::src::threads::_xmlDoc;
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

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
pub type xmlAttrPtr = * mut crate::src::threads::_xmlAttr;
pub type xmlAttr = crate::src::threads::_xmlAttr;
pub type xmlNodePtr = * mut crate::src::threads::_xmlNode;
pub type xmlNode = crate::src::threads::_xmlNode;
pub type xmlDocPtr = * mut crate::src::threads::_xmlDoc;
pub type xmlDoc = crate::src::threads::_xmlDoc;
pub type xmlEntityPtr = * mut crate::src::threads::_xmlEntity;
pub type xmlEntity = crate::src::threads::_xmlEntity;
// #[derive(Copy, Clone)]

pub type _xmlEntity = crate::src::threads::_xmlEntity;
pub type xmlEntityType = u32;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type xmlElementContentPtr = * mut crate::src::threads::_xmlElementContent;
pub type xmlElementContent = crate::src::threads::_xmlElementContent;
// #[derive(Copy, Clone)]

pub type _xmlElementContent = crate::src::threads::_xmlElementContent;
pub type xmlElementContentOccur = u32;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub type xmlElementContentType = u32;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub type xmlEnumerationPtr = * mut crate::src::threads::_xmlEnumeration;
pub type xmlEnumeration = crate::src::threads::_xmlEnumeration;
// #[derive(Copy, Clone)]

pub type _xmlEnumeration = crate::src::threads::_xmlEnumeration;
pub type xmlBufferAllocationScheme = u32;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
// #[derive(Copy, Clone)]

pub type _xmlBuffer = crate::src::tree::_xmlBuffer;
pub type xmlBuffer = crate::src::tree::_xmlBuffer;
pub type xmlBufferPtr = * mut crate::src::tree::_xmlBuffer;
pub type xmlAttributeDefault = u32;
pub const XML_ATTRIBUTE_FIXED: xmlAttributeDefault = 4;
pub const XML_ATTRIBUTE_IMPLIED: xmlAttributeDefault = 3;
pub const XML_ATTRIBUTE_REQUIRED: xmlAttributeDefault = 2;
pub const XML_ATTRIBUTE_NONE: xmlAttributeDefault = 1;
// #[derive(Copy, Clone)]

pub type _xmlAttribute = crate::src::tree::_xmlAttribute;
pub type xmlAttribute = crate::src::tree::_xmlAttribute;
pub type xmlAttributePtr = * mut crate::src::tree::_xmlAttribute;
pub type xmlElementTypeVal = u32;
pub const XML_ELEMENT_TYPE_ELEMENT: xmlElementTypeVal = 4;
pub const XML_ELEMENT_TYPE_MIXED: xmlElementTypeVal = 3;
pub const XML_ELEMENT_TYPE_ANY: xmlElementTypeVal = 2;
pub const XML_ELEMENT_TYPE_EMPTY: xmlElementTypeVal = 1;
pub const XML_ELEMENT_TYPE_UNDEFINED: xmlElementTypeVal = 0;
pub type xmlRegexp = crate::src::xmlregexp::_xmlRegexp;
pub type xmlRegexpPtr = * mut crate::src::xmlregexp::_xmlRegexp;
// #[derive(Copy, Clone)]

pub type _xmlElement = crate::src::tree::_xmlElement;
pub type xmlElement = crate::src::tree::_xmlElement;
pub type xmlElementPtr = * mut crate::src::tree::_xmlElement;
pub type xmlNsPtr = * mut crate::src::threads::_xmlNs;
pub type xmlDtd = crate::src::threads::_xmlDtd;
pub type xmlDtdPtr = * mut crate::src::threads::_xmlDtd;
pub const XML_SAVE_CHAR_INVALID: C2RustUnnamed_0 = 1401;
pub const XML_FROM_OUTPUT: C2RustUnnamed = 7;
pub const XML_SAVE_NO_DOCTYPE: C2RustUnnamed_0 = 1402;
pub const XML_SAVE_UNKNOWN_ENCODING: C2RustUnnamed_0 = 1403;
pub const XML_SAVE_NOT_UTF8: C2RustUnnamed_0 = 1400;
pub const XML_ERR_NO_MEMORY: C2RustUnnamed_0 = 2;
pub type xmlSaveCtxt<'a> = crate::src::xmlsave::_xmlSaveCtxt<'a>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSaveCtxt<'a> {
    pub _private: * mut core::ffi::c_void,
    pub type_0: i32,
    pub fd: i32,
    pub filename: Option<&'a u8>,
    pub encoding: * const u8,
    pub handler: * mut crate::src::threads::_xmlCharEncodingHandler,
    pub buf: * mut crate::src::threads::_xmlOutputBuffer,
    pub options: i32,
    pub level: i32,
    pub format: i32,
    pub indent: [i8; 61],
    pub indent_nr: i32,
    pub indent_size: i32,
    pub escape: Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>,
    pub escapeAttr: Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>,
}
impl<'a> _xmlSaveCtxt<'a> {
    pub const fn new() -> Self {
        _xmlSaveCtxt {
        _private: (0 as * mut core::ffi::c_void),
        type_0: 0,
        fd: 0,
        filename: None,
        encoding: (0 as * const u8),
        handler: (0 as * mut crate::src::threads::_xmlCharEncodingHandler),
        buf: (0 as * mut crate::src::threads::_xmlOutputBuffer),
        options: 0,
        level: 0,
        format: 0,
        indent: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        indent_nr: 0,
        indent_size: 0,
        escape: None,
        escapeAttr: None
        }
    }
}

impl<'a> std::default::Default for _xmlSaveCtxt<'a> {
    fn default() -> Self { _xmlSaveCtxt::new() }
}

pub type xmlSaveCtxtPtr<'a> = * mut crate::src::xmlsave::_xmlSaveCtxt<'a>;
pub const XML_SAVE_NO_EMPTY: C2RustUnnamed_1 = 4;
pub type xmlNotationTablePtr = * mut crate::src::xmlsave::_xmlHashTable;
pub type xmlNotationTable = crate::src::xmlsave::_xmlHashTable;
pub const XML_SAVE_NO_XHTML: C2RustUnnamed_1 = 8;
pub const XML_SAVE_XHTML: C2RustUnnamed_1 = 16;
pub const XML_SAVE_NO_DECL: C2RustUnnamed_1 = 2;
pub type xmlGenericErrorFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub const XML_CHAR_ENCODING_ASCII: xmlCharEncoding = 22;
pub type xmlCharEncoding = i32;
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
pub const XML_SAVE_AS_XML: C2RustUnnamed_1 = 32;
pub const XML_SAVE_FORMAT: C2RustUnnamed_1 = 1;
pub type htmlDocPtr = * mut crate::src::threads::_xmlDoc;
pub const XML_SAVE_AS_HTML: C2RustUnnamed_1 = 64;
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
pub const XML_ERR_INTERNAL_ERROR: C2RustUnnamed_0 = 1;
pub const XML_ERR_OK: C2RustUnnamed_0 = 0;
pub type C2RustUnnamed_1 = u32;
pub const XML_SAVE_WSNONSIG: C2RustUnnamed_1 = 128;
#[no_mangle]
pub unsafe extern "C" fn xmlIsXHTML(
    mut systemID: * const u8,
    mut publicID: * const u8,
) -> i32 {
    if systemID.is_null() && publicID.is_null() {
        return -(1 as i32);
    }
    if !publicID.is_null() {
        if xmlStrEqual(
            publicID,
            b"-//W3C//DTD XHTML 1.0 Strict//EN\0" as *const u8 as *const i8
                as *mut xmlChar,
        ) != 0
        {
            return 1 as i32;
        }
        if xmlStrEqual(
            publicID,
            b"-//W3C//DTD XHTML 1.0 Frameset//EN\0" as *const u8 as *const i8
                as *mut xmlChar,
        ) != 0
        {
            return 1 as i32;
        }
        if xmlStrEqual(
            publicID,
            b"-//W3C//DTD XHTML 1.0 Transitional//EN\0" as *const u8
                as *const i8 as *mut xmlChar,
        ) != 0
        {
            return 1 as i32;
        }
    }
    if !systemID.is_null() {
        if xmlStrEqual(
            systemID,
            b"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\0" as *const u8
                as *const i8 as *mut xmlChar,
        ) != 0
        {
            return 1 as i32;
        }
        if xmlStrEqual(
            systemID,
            b"http://www.w3.org/TR/xhtml1/DTD/xhtml1-frameset.dtd\0" as *const u8
                as *const i8 as *mut xmlChar,
        ) != 0
        {
            return 1 as i32;
        }
        if xmlStrEqual(
            systemID,
            b"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\0" as *const u8
                as *const i8 as *mut xmlChar,
        ) != 0
        {
            return 1 as i32;
        }
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlSaveErrMemory(mut extra: * const i8) {
    __xmlSimpleError(
        XML_FROM_OUTPUT as i32,
        XML_ERR_NO_MEMORY as i32,
        0 as xmlNodePtr,
        0 as *const i8,
        extra,
    );
}
unsafe extern "C" fn xmlSaveErr(
    mut code: i32,
    mut node: * mut crate::src::threads::_xmlNode,
    mut extra: * const i8,
) {
    let mut msg: * const i8 = 0 as *const i8;
    match code {
        1400 => {
            msg = b"string is not in UTF-8\n\0" as *const u8 as *const i8;
        }
        1401 => {
            msg = b"invalid character value\n\0" as *const u8 as *const i8;
        }
        1403 => {
            msg = b"unknown encoding %s\n\0" as *const u8 as *const i8;
        }
        1402 => {
            msg = b"document has no DOCTYPE\n\0" as *const u8 as *const i8;
        }
        _ => {
            msg = b"unexpected error number\n\0" as *const u8 as *const i8;
        }
    }
    __xmlSimpleError(XML_FROM_OUTPUT as i32, code, node, msg, extra);
}
unsafe extern "C" fn xmlSerializeHexCharRef(
    mut out: * mut u8,
    mut val: i32,
) -> * mut u8 {
    let mut ptr: * mut u8 = 0 as *mut u8;
    let mut fresh0 = out;
    out = out.offset(1);
    *fresh0 = '&' as i32 as u8;
    let mut fresh1 = out;
    out = out.offset(1);
    *fresh1 = '#' as i32 as u8;
    let mut fresh2 = out;
    out = out.offset(1);
    *fresh2 = 'x' as i32 as u8;
    if val < 0x10 as i32 {
        ptr = out;
    } else if val < 0x100 as i32 {
        ptr = out.offset(1 as i32 as isize);
    } else if val < 0x1000 as i32 {
        ptr = out.offset(2 as i32 as isize);
    } else if val < 0x10000 as i32 {
        ptr = out.offset(3 as i32 as isize);
    } else if val < 0x100000 as i32 {
        ptr = out.offset(4 as i32 as isize);
    } else {
        ptr = out.offset(5 as i32 as isize);
    }
    out = ptr.offset(1 as i32 as isize);
    while val > 0 as i32 {
        match val & 0xf as i32 {
            0 => {
                let mut fresh3 = ptr;
                ptr = ptr.offset(-1);
                *fresh3 = '0' as i32 as u8;
            }
            1 => {
                let mut fresh4 = ptr;
                ptr = ptr.offset(-1);
                *fresh4 = '1' as i32 as u8;
            }
            2 => {
                let mut fresh5 = ptr;
                ptr = ptr.offset(-1);
                *fresh5 = '2' as i32 as u8;
            }
            3 => {
                let mut fresh6 = ptr;
                ptr = ptr.offset(-1);
                *fresh6 = '3' as i32 as u8;
            }
            4 => {
                let mut fresh7 = ptr;
                ptr = ptr.offset(-1);
                *fresh7 = '4' as i32 as u8;
            }
            5 => {
                let mut fresh8 = ptr;
                ptr = ptr.offset(-1);
                *fresh8 = '5' as i32 as u8;
            }
            6 => {
                let mut fresh9 = ptr;
                ptr = ptr.offset(-1);
                *fresh9 = '6' as i32 as u8;
            }
            7 => {
                let mut fresh10 = ptr;
                ptr = ptr.offset(-1);
                *fresh10 = '7' as i32 as u8;
            }
            8 => {
                let mut fresh11 = ptr;
                ptr = ptr.offset(-1);
                *fresh11 = '8' as i32 as u8;
            }
            9 => {
                let mut fresh12 = ptr;
                ptr = ptr.offset(-1);
                *fresh12 = '9' as i32 as u8;
            }
            10 => {
                let mut fresh13 = ptr;
                ptr = ptr.offset(-1);
                *fresh13 = 'A' as i32 as u8;
            }
            11 => {
                let mut fresh14 = ptr;
                ptr = ptr.offset(-1);
                *fresh14 = 'B' as i32 as u8;
            }
            12 => {
                let mut fresh15 = ptr;
                ptr = ptr.offset(-1);
                *fresh15 = 'C' as i32 as u8;
            }
            13 => {
                let mut fresh16 = ptr;
                ptr = ptr.offset(-1);
                *fresh16 = 'D' as i32 as u8;
            }
            14 => {
                let mut fresh17 = ptr;
                ptr = ptr.offset(-1);
                *fresh17 = 'E' as i32 as u8;
            }
            15 => {
                let mut fresh18 = ptr;
                ptr = ptr.offset(-1);
                *fresh18 = 'F' as i32 as u8;
            }
            _ => {
                let mut fresh19 = ptr;
                ptr = ptr.offset(-1);
                *fresh19 = '0' as i32 as u8;
            }
        }
        val >>= 4 as i32;
    }
    let mut fresh20 = out;
    out = out.offset(1);
    *fresh20 = ';' as i32 as u8;
    *out = 0 as i32 as u8;
    return out;
}
unsafe extern "C" fn xmlEscapeEntities(
    mut out: * mut u8,
    mut outlen: * mut i32,
    mut in_0: * const u8,
    mut inlen: * mut i32,
) -> i32 {
    let mut current_block: u64;
    let mut outstart: * mut u8 = out;
    let mut base: * const u8 = in_0;
    let mut outend: * mut u8 = out.offset(*outlen as isize);
    let mut inend: * const u8 = 0 as *const u8;
    let mut val: i32 = 0;
    inend = in_0.offset(*inlen as isize);
    loop {
        if !(in_0 < inend && out < outend) {
            current_block = 7419121793134201633;
            break;
        }
        if *in_0 as i32 == '<' as i32 {
            if (outend.offset_from(out) as i64)
                < 4 as i32 as i64
            {
                current_block = 7419121793134201633;
                break;
            }
            let mut fresh21 = out;
            out = out.offset(1);
            *fresh21 = '&' as i32 as u8;
            let mut fresh22 = out;
            out = out.offset(1);
            *fresh22 = 'l' as i32 as u8;
            let mut fresh23 = out;
            out = out.offset(1);
            *fresh23 = 't' as i32 as u8;
            let mut fresh24 = out;
            out = out.offset(1);
            *fresh24 = ';' as i32 as u8;
            in_0 = in_0.offset(1);
        } else if *in_0 as i32 == '>' as i32 {
            if (outend.offset_from(out) as i64)
                < 4 as i32 as i64
            {
                current_block = 7419121793134201633;
                break;
            }
            let mut fresh25 = out;
            out = out.offset(1);
            *fresh25 = '&' as i32 as u8;
            let mut fresh26 = out;
            out = out.offset(1);
            *fresh26 = 'g' as i32 as u8;
            let mut fresh27 = out;
            out = out.offset(1);
            *fresh27 = 't' as i32 as u8;
            let mut fresh28 = out;
            out = out.offset(1);
            *fresh28 = ';' as i32 as u8;
            in_0 = in_0.offset(1);
        } else if *in_0 as i32 == '&' as i32 {
            if (outend.offset_from(out) as i64)
                < 5 as i32 as i64
            {
                current_block = 7419121793134201633;
                break;
            }
            let mut fresh29 = out;
            out = out.offset(1);
            *fresh29 = '&' as i32 as u8;
            let mut fresh30 = out;
            out = out.offset(1);
            *fresh30 = 'a' as i32 as u8;
            let mut fresh31 = out;
            out = out.offset(1);
            *fresh31 = 'm' as i32 as u8;
            let mut fresh32 = out;
            out = out.offset(1);
            *fresh32 = 'p' as i32 as u8;
            let mut fresh33 = out;
            out = out.offset(1);
            *fresh33 = ';' as i32 as u8;
            in_0 = in_0.offset(1);
        } else if *in_0 as i32 >= 0x20 as i32
                && (*in_0 as i32) < 0x80 as i32
                || *in_0 as i32 == '\n' as i32
                || *in_0 as i32 == '\t' as i32
            {
            let mut fresh34 = in_0;
            in_0 = in_0.offset(1);
            let mut fresh35 = out;
            out = out.offset(1);
            *fresh35 = *fresh34;
        } else if *in_0 as i32 >= 0x80 as i32 {
            if (outend.offset_from(out) as i64)
                < 11 as i32 as i64
            {
                current_block = 7419121793134201633;
                break;
            }
            if (*in_0 as i32) < 0xc0 as i32 {
                xmlSaveErr(
                    XML_SAVE_NOT_UTF8 as i32,
                    0 as xmlNodePtr,
                    0 as *const i8,
                );
                in_0 = in_0.offset(1);
                current_block = 15478913418544193884;
                break;
            } else {
                if (*in_0 as i32) < 0xe0 as i32 {
                    if (inend.offset_from(in_0) as i64)
                        < 2 as i32 as i64
                    {
                        current_block = 7419121793134201633;
                        break;
                    }
                    val = *in_0.offset(0 as i32 as isize) as i32
                        & 0x1f as i32;
                    val <<= 6 as i32;
                    val
                        |= *in_0.offset(1 as i32 as isize) as i32
                            & 0x3f as i32;
                    in_0 = in_0.offset(2 as i32 as isize);
                } else if (*in_0 as i32) < 0xf0 as i32 {
                    if (inend.offset_from(in_0) as i64)
                        < 3 as i32 as i64
                    {
                        current_block = 7419121793134201633;
                        break;
                    }
                    val = *in_0.offset(0 as i32 as isize) as i32
                        & 0xf as i32;
                    val <<= 6 as i32;
                    val
                        |= *in_0.offset(1 as i32 as isize) as i32
                            & 0x3f as i32;
                    val <<= 6 as i32;
                    val
                        |= *in_0.offset(2 as i32 as isize) as i32
                            & 0x3f as i32;
                    in_0 = in_0.offset(3 as i32 as isize);
                } else if (*in_0 as i32) < 0xf8 as i32 {
                    if (inend.offset_from(in_0) as i64)
                        < 4 as i32 as i64
                    {
                        current_block = 7419121793134201633;
                        break;
                    }
                    val = *in_0.offset(0 as i32 as isize) as i32
                        & 0x7 as i32;
                    val <<= 6 as i32;
                    val
                        |= *in_0.offset(1 as i32 as isize) as i32
                            & 0x3f as i32;
                    val <<= 6 as i32;
                    val
                        |= *in_0.offset(2 as i32 as isize) as i32
                            & 0x3f as i32;
                    val <<= 6 as i32;
                    val
                        |= *in_0.offset(3 as i32 as isize) as i32
                            & 0x3f as i32;
                    in_0 = in_0.offset(4 as i32 as isize);
                } else {
                    xmlSaveErr(
                        XML_SAVE_CHAR_INVALID as i32,
                        0 as xmlNodePtr,
                        0 as *const i8,
                    );
                    in_0 = in_0.offset(1);
                    current_block = 15478913418544193884;
                    break;
                }
                if if val < 0x100 as i32 {
                    (0x9 as i32 <= val && val <= 0xa as i32
                        || val == 0xd as i32 || 0x20 as i32 <= val)
                        as i32
                } else {
                    (0x100 as i32 <= val && val <= 0xd7ff as i32
                        || 0xe000 as i32 <= val && val <= 0xfffd as i32
                        || 0x10000 as i32 <= val
                            && val <= 0x10ffff as i32) as i32
                } == 0
                {
                    xmlSaveErr(
                        XML_SAVE_CHAR_INVALID as i32,
                        0 as xmlNodePtr,
                        0 as *const i8,
                    );
                    in_0 = in_0.offset(1);
                    current_block = 15478913418544193884;
                    break;
                } else {
                    out = xmlSerializeHexCharRef(out, val);
                }
            }
        } else if 0x9 as i32 <= *in_0 as i32
                && *in_0 as i32 <= 0xa as i32
                || *in_0 as i32 == 0xd as i32
                || 0x20 as i32 <= *in_0 as i32
            {
            if (outend.offset_from(out) as i64)
                < 6 as i32 as i64
            {
                current_block = 7419121793134201633;
                break;
            }
            let mut fresh36 = in_0;
            in_0 = in_0.offset(1);
            out = xmlSerializeHexCharRef(out, *fresh36 as i32);
        } else {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"xmlEscapeEntities : char out of range\n\0" as *const u8
                    as *const i8,
            );
            in_0 = in_0.offset(1);
            current_block = 15478913418544193884;
            break;
        }
    }
    match current_block {
        15478913418544193884 => {
            *outlen = out.offset_from(outstart) as i64 as i32;
            *inlen = in_0.offset_from(base) as i64 as i32;
            return -(1 as i32);
        }
        _ => {
            *outlen = out.offset_from(outstart) as i64 as i32;
            *inlen = in_0.offset_from(base) as i64 as i32;
            return 0 as i32;
        }
    };
}
unsafe extern "C" fn xmlSaveCtxtInit<'a1>(mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>) {
    let mut i: i32 = 0;
    let mut len: i32 = 0;
    if ctxt.is_null() {
        return;
    }
    if ((*ctxt).encoding).is_null() && ((*ctxt).escape).is_none() {
        let fresh37 = &mut ((*ctxt).escape);
        *fresh37 = Some(
            xmlEscapeEntities,
        );
    }
    len = xmlStrlen(*__xmlTreeIndentString() as *mut xmlChar);
    if (*__xmlTreeIndentString()).is_null() || len == 0 as i32 {
        memset(
            &mut *((*ctxt).indent).as_mut_ptr().offset(0 as i32 as isize)
                as *mut i8 as *mut libc::c_void,
            0 as i32,
            (60 as i32 + 1 as i32) as u64,
        );
    } else {
        (*ctxt).indent_size = len;
        (*ctxt).indent_nr = 60 as i32 / (*ctxt).indent_size;
        i = 0 as i32;
        while i < (*ctxt).indent_nr {
            memcpy(
                &mut *((*ctxt).indent)
                    .as_mut_ptr()
                    .offset((i * (*ctxt).indent_size) as isize) as *mut i8
                    as *mut libc::c_void,
                *__xmlTreeIndentString() as *const libc::c_void,
                (*ctxt).indent_size as u64,
            );
            i += 1;
        }
        (*ctxt)
            .indent[((*ctxt).indent_nr * (*ctxt).indent_size)
            as usize] = 0 as i32 as i8;
    }
    if *__xmlSaveNoEmptyTags() != 0 {
        (*ctxt).options |= XML_SAVE_NO_EMPTY as i32;
    }
}
unsafe extern "C" fn xmlFreeSaveCtxt<'a1>(mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>) {
    if ctxt.is_null() {
        return;
    }
    if !((*ctxt).encoding).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).encoding as *mut i8 as *mut libc::c_void);
    }
    if !((*ctxt).buf).is_null() {
        xmlOutputBufferClose((*ctxt).buf);
    }
    xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void);
}
unsafe extern "C" fn xmlNewSaveCtxt<'a1>(
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::xmlsave::_xmlSaveCtxt<'a1> {
    let mut ret: * mut crate::src::xmlsave::_xmlSaveCtxt<'_> = 0 as *mut xmlSaveCtxt;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlSaveCtxt>() as u64) as xmlSaveCtxtPtr;
    if ret.is_null() {
        xmlSaveErrMemory(
            b"creating saving context\0" as *const u8 as *const i8,
        );
        return 0 as xmlSaveCtxtPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSaveCtxt>() as u64,
    );
    if !encoding.is_null() {
        let fresh38 = &mut ((*ret).handler);
        *fresh38 = xmlFindCharEncodingHandler(encoding);
        if ((*ret).handler).is_null() {
            xmlSaveErr(
                XML_SAVE_UNKNOWN_ENCODING as i32,
                0 as xmlNodePtr,
                encoding,
            );
            xmlFreeSaveCtxt(ret);
            return 0 as xmlSaveCtxtPtr;
        }
        let fresh39 = &mut ((*ret).encoding);
        *fresh39 = xmlStrdup(encoding as *const xmlChar);
        let fresh40 = &mut ((*ret).escape);
        *fresh40 = None;
    }
    xmlSaveCtxtInit(ret);
    if (*ret).options & XML_SAVE_NO_EMPTY as i32 != 0
        && options & XML_SAVE_NO_EMPTY as i32 == 0
    {
        options |= XML_SAVE_NO_EMPTY as i32;
    }
    (*ret).options = options;
    if options & XML_SAVE_FORMAT as i32 != 0 {
        (*ret).format = 1 as i32;
    } else if options & XML_SAVE_WSNONSIG as i32 != 0 {
        (*ret).format = 2 as i32;
    }
    return ret;
}
unsafe extern "C" fn xmlAttrSerializeContent(
    mut buf: * mut crate::src::threads::_xmlOutputBuffer,
    mut attr: * mut crate::src::threads::_xmlAttr,
) {
    let mut children: * mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    children = (*attr).children;
    while !children.is_null() {
        match (*children).type_0 as u32 {
            3 => {
                xmlBufAttrSerializeTxtContent(
                    (*buf).buffer,
                    (*attr).doc,
                    attr,
                    (*children).content,
                );
            }
            5 => {
                xmlBufAdd(
                    (*buf).buffer,
                    b"&\0" as *const u8 as *const i8 as *mut xmlChar,
                    1 as i32,
                );
                xmlBufAdd((*buf).buffer, (*children).name, xmlStrlen((*children).name));
                xmlBufAdd(
                    (*buf).buffer,
                    b";\0" as *const u8 as *const i8 as *mut xmlChar,
                    1 as i32,
                );
            }
            _ => {}
        }
        children = (*children).next;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufDumpNotationTable(
    mut buf: * mut crate::src::xmlstring::_xmlBuf,
    mut table: * mut crate::src::xmlsave::_xmlHashTable,
) {
    let mut buffer: * mut crate::src::tree::_xmlBuffer = 0 as *mut xmlBuffer;
    buffer = xmlBufferCreate();
    if buffer.is_null() {
        return;
    }
    xmlBufferSetAllocationScheme(buffer, XML_BUFFER_ALLOC_DOUBLEIT);
    xmlDumpNotationTable(buffer, table);
    xmlBufMergeBuffer(buf, buffer);
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufDumpElementDecl(
    mut buf: * mut crate::src::xmlstring::_xmlBuf,
    mut elem: * mut crate::src::tree::_xmlElement,
) {
    let mut buffer: * mut crate::src::tree::_xmlBuffer = 0 as *mut xmlBuffer;
    buffer = xmlBufferCreate();
    if buffer.is_null() {
        return;
    }
    xmlBufferSetAllocationScheme(buffer, XML_BUFFER_ALLOC_DOUBLEIT);
    xmlDumpElementDecl(buffer, elem);
    xmlBufMergeBuffer(buf, buffer);
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufDumpAttributeDecl(
    mut buf: * mut crate::src::xmlstring::_xmlBuf,
    mut attr: * mut crate::src::tree::_xmlAttribute,
) {
    let mut buffer: * mut crate::src::tree::_xmlBuffer = 0 as *mut xmlBuffer;
    buffer = xmlBufferCreate();
    if buffer.is_null() {
        return;
    }
    xmlBufferSetAllocationScheme(buffer, XML_BUFFER_ALLOC_DOUBLEIT);
    xmlDumpAttributeDecl(buffer, attr);
    xmlBufMergeBuffer(buf, buffer);
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufDumpEntityDecl(
    mut buf: * mut crate::src::xmlstring::_xmlBuf,
    mut ent: * mut crate::src::threads::_xmlEntity,
) {
    let mut buffer: * mut crate::src::tree::_xmlBuffer = 0 as *mut xmlBuffer;
    buffer = xmlBufferCreate();
    if buffer.is_null() {
        return;
    }
    xmlBufferSetAllocationScheme(buffer, XML_BUFFER_ALLOC_DOUBLEIT);
    xmlDumpEntityDecl(buffer, ent);
    xmlBufMergeBuffer(buf, buffer);
}
unsafe extern "C" fn xmlSaveSwitchEncoding<'a1>(
    mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>,
    mut encoding: * const i8,
) -> i32 {
    let mut buf: * mut crate::src::threads::_xmlOutputBuffer = (*ctxt).buf;
    if !encoding.is_null() && ((*buf).encoder).is_null() && ((*buf).conv).is_null() {
        let fresh41 = &mut ((*buf).encoder);
        *fresh41 = xmlFindCharEncodingHandler(encoding);
        if ((*buf).encoder).is_null() {
            xmlSaveErr(
                XML_SAVE_UNKNOWN_ENCODING as i32,
                0 as xmlNodePtr,
                encoding,
            );
            return -(1 as i32);
        }
        let fresh42 = &mut ((*buf).conv);
        *fresh42 = xmlBufCreate();
        if ((*buf).conv).is_null() {
            xmlCharEncCloseFunc((*buf).encoder);
            xmlSaveErrMemory(
                b"creating encoding buffer\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        xmlCharEncOutput(buf, 1 as i32);
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlSaveClearEncoding<'a1>(mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>) -> i32 {
    let mut buf: * mut crate::src::threads::_xmlOutputBuffer = (*ctxt).buf;
    xmlOutputBufferFlush(buf);
    xmlCharEncCloseFunc((*buf).encoder);
    xmlBufFree((*buf).conv);
    let fresh43 = &mut ((*buf).encoder);
    *fresh43 = 0 as xmlCharEncodingHandlerPtr;
    let fresh44 = &mut ((*buf).conv);
    *fresh44 = 0 as xmlBufPtr;
    return 0 as i32;
}
unsafe extern "C" fn xmlOutputBufferWriteWSNonSig<'a1>(
    mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>,
    mut extra: i32,
) {
    let mut i: i32 = 0;
    if ctxt.is_null() || ((*ctxt).buf).is_null() {
        return;
    }
    xmlOutputBufferWrite(
        (*ctxt).buf,
        1 as i32,
        b"\n\0" as *const u8 as *const i8,
    );
    i = 0 as i32;
    while i < (*ctxt).level + extra {
        xmlOutputBufferWrite(
            (*ctxt).buf,
            (*ctxt).indent_size
                * (if (*ctxt).level + extra - i > (*ctxt).indent_nr {
                    (*ctxt).indent_nr
                } else {
                    (*ctxt).level + extra - i
                }),
            ((*ctxt).indent).as_mut_ptr(),
        );
        i += (*ctxt).indent_nr;
    }
}
unsafe extern "C" fn xmlNsDumpOutput<'a1>(
    mut buf: * mut crate::src::threads::_xmlOutputBuffer,
    mut cur: * mut crate::src::threads::_xmlNs,
    mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>,
) {
    if cur.is_null() || buf.is_null() {
        return;
    }
    if (*cur).type_0 as u32 == XML_NAMESPACE_DECL as i32 as u32
        && !((*cur).href).is_null()
    {
        if xmlStrEqual(
            (*cur).prefix,
            b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
        {
            return;
        }
        if !ctxt.is_null() && (*ctxt).format == 2 as i32 {
            xmlOutputBufferWriteWSNonSig(ctxt, 2 as i32);
        } else {
            xmlOutputBufferWrite(
                buf,
                1 as i32,
                b" \0" as *const u8 as *const i8,
            );
        }
        if !((*cur).prefix).is_null() {
            xmlOutputBufferWrite(
                buf,
                6 as i32,
                b"xmlns:\0" as *const u8 as *const i8,
            );
            xmlOutputBufferWriteString(buf, (*cur).prefix as *const i8);
        } else {
            xmlOutputBufferWrite(
                buf,
                5 as i32,
                b"xmlns\0" as *const u8 as *const i8,
            );
        }
        xmlOutputBufferWrite(
            buf,
            1 as i32,
            b"=\0" as *const u8 as *const i8,
        );
        xmlBufWriteQuotedString((*buf).buffer, (*cur).href);
    }
}
unsafe extern "C" fn xmlNsDumpOutputCtxt<'a1>(mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>, mut cur: * mut crate::src::threads::_xmlNs) {
    xmlNsDumpOutput((*ctxt).buf, cur, ctxt);
}
unsafe extern "C" fn xmlNsListDumpOutputCtxt<'a1>(
    mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>,
    mut cur: * mut crate::src::threads::_xmlNs,
) {
    while !cur.is_null() {
        xmlNsDumpOutput((*ctxt).buf, cur, ctxt);
        cur = (*cur).next;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlNsListDumpOutput(
    mut buf: * mut crate::src::threads::_xmlOutputBuffer,
    mut cur: * mut crate::src::threads::_xmlNs,
) {
    while !cur.is_null() {
        xmlNsDumpOutput(buf, cur, 0 as xmlSaveCtxtPtr);
        cur = (*cur).next;
    }
}
unsafe extern "C" fn xmlDtdDumpOutput<'a1>(mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>, mut dtd: * mut crate::src::threads::_xmlDtd) {
    let mut buf: * mut crate::src::threads::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    let mut cur: * mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut format: i32 = 0;
    let mut level: i32 = 0;
    if dtd.is_null() {
        return;
    }
    if ctxt.is_null() || ((*ctxt).buf).is_null() {
        return;
    }
    buf = (*ctxt).buf;
    xmlOutputBufferWrite(
        buf,
        10 as i32,
        b"<!DOCTYPE \0" as *const u8 as *const i8,
    );
    xmlOutputBufferWriteString(buf, (*dtd).name as *const i8);
    if !((*dtd).ExternalID).is_null() {
        xmlOutputBufferWrite(
            buf,
            8 as i32,
            b" PUBLIC \0" as *const u8 as *const i8,
        );
        xmlBufWriteQuotedString((*buf).buffer, (*dtd).ExternalID);
        xmlOutputBufferWrite(
            buf,
            1 as i32,
            b" \0" as *const u8 as *const i8,
        );
        xmlBufWriteQuotedString((*buf).buffer, (*dtd).SystemID);
    } else if !((*dtd).SystemID).is_null() {
        xmlOutputBufferWrite(
            buf,
            8 as i32,
            b" SYSTEM \0" as *const u8 as *const i8,
        );
        xmlBufWriteQuotedString((*buf).buffer, (*dtd).SystemID);
    }
    if ((*dtd).entities).is_null() && ((*dtd).elements).is_null()
        && ((*dtd).attributes).is_null() && ((*dtd).notations).is_null()
        && ((*dtd).pentities).is_null()
    {
        xmlOutputBufferWrite(
            buf,
            1 as i32,
            b">\0" as *const u8 as *const i8,
        );
        return;
    }
    xmlOutputBufferWrite(
        buf,
        3 as i32,
        b" [\n\0" as *const u8 as *const i8,
    );
    if !((*dtd).notations).is_null()
        && (((*dtd).doc).is_null() || (*(*dtd).doc).intSubset == dtd)
    {
        xmlBufDumpNotationTable((*buf).buffer, (*dtd).notations as xmlNotationTablePtr);
    }
    format = (*ctxt).format;
    level = (*ctxt).level;
    (*ctxt).format = 0 as i32;
    (*ctxt).level = -(1 as i32);
    cur = (*dtd).children;
    while !cur.is_null() {
        xmlNodeDumpOutputInternal(ctxt, cur);
        cur = (*cur).next;
    }
    (*ctxt).format = format;
    (*ctxt).level = level;
    xmlOutputBufferWrite(
        buf,
        2 as i32,
        b"]>\0" as *const u8 as *const i8,
    );
}
unsafe extern "C" fn xmlAttrDumpOutput<'a1>(mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>, mut cur: * mut crate::src::threads::_xmlAttr) {
    let mut buf: * mut crate::src::threads::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    if cur.is_null() {
        return;
    }
    buf = (*ctxt).buf;
    if buf.is_null() {
        return;
    }
    if (*ctxt).format == 2 as i32 {
        xmlOutputBufferWriteWSNonSig(ctxt, 2 as i32);
    } else {
        xmlOutputBufferWrite(
            buf,
            1 as i32,
            b" \0" as *const u8 as *const i8,
        );
    }
    if !((*cur).ns).is_null() && !((*(*cur).ns).prefix).is_null() {
        xmlOutputBufferWriteString(buf, (*(*cur).ns).prefix as *const i8);
        xmlOutputBufferWrite(
            buf,
            1 as i32,
            b":\0" as *const u8 as *const i8,
        );
    }
    xmlOutputBufferWriteString(buf, (*cur).name as *const i8);
    xmlOutputBufferWrite(
        buf,
        2 as i32,
        b"=\"\0" as *const u8 as *const i8,
    );
    xmlAttrSerializeContent(buf, cur);
    xmlOutputBufferWrite(
        buf,
        1 as i32,
        b"\"\0" as *const u8 as *const i8,
    );
}
unsafe extern "C" fn htmlNodeDumpOutputInternal<'a1>(
    mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>,
    mut cur: * mut crate::src::threads::_xmlNode,
) -> i32 {
    let mut oldenc: * const u8 = 0 as *const xmlChar;
    let mut oldctxtenc: * const u8 = (*ctxt).encoding;
    let mut encoding: * const u8 = (*ctxt).encoding;
    let mut buf: * mut crate::src::threads::_xmlOutputBuffer = (*ctxt).buf;
    let mut switched_encoding: i32 = 0 as i32;
    let mut doc: * mut crate::src::threads::_xmlDoc = 0 as *mut xmlDoc;
    xmlInitParser();
    doc = (*cur).doc;
    if !doc.is_null() {
        oldenc = (*doc).encoding;
        if !((*ctxt).encoding).is_null() {
            let fresh45 = &mut ((*doc).encoding);
            *fresh45 = (*ctxt).encoding as *mut xmlChar;
        } else if !((*doc).encoding).is_null() {
            encoding = (*doc).encoding;
        }
    }
    if !encoding.is_null() && !doc.is_null() {
        htmlSetMetaEncoding(doc, encoding);
    }
    if encoding.is_null() && !doc.is_null() {
        encoding = htmlGetMetaEncoding(doc);
    }
    if encoding.is_null() {
        encoding = b"HTML\0" as *const u8 as *const i8 as *mut xmlChar;
    }
    if !encoding.is_null() && oldctxtenc.is_null() && ((*buf).encoder).is_null()
        && ((*buf).conv).is_null()
    {
        if xmlSaveSwitchEncoding(ctxt, encoding as *const i8)
            < 0 as i32
        {
            let fresh46 = &mut ((*doc).encoding);
            *fresh46 = oldenc;
            return -(1 as i32);
        }
        switched_encoding = 1 as i32;
    }
    if (*ctxt).options & XML_SAVE_FORMAT as i32 != 0 {
        htmlNodeDumpFormatOutput(
            buf,
            doc,
            cur,
            encoding as *const i8,
            1 as i32,
        );
    } else {
        htmlNodeDumpFormatOutput(
            buf,
            doc,
            cur,
            encoding as *const i8,
            0 as i32,
        );
    }
    if switched_encoding != 0 && oldctxtenc.is_null() {
        xmlSaveClearEncoding(ctxt);
    }
    if !doc.is_null() {
        let fresh47 = &mut ((*doc).encoding);
        *fresh47 = oldenc;
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlNodeDumpOutputInternal<'a1>(
    mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>,
    mut cur: * mut crate::src::threads::_xmlNode,
) {
    let mut format: i32 = (*ctxt).format;
    let mut tmp: * mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut root: * mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut unformattedNode: * mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut parent: * mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut attr: * mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    let mut start: * mut u8 = 0 as *mut xmlChar;
    let mut end: * mut u8 = 0 as *mut xmlChar;
    let mut buf: * mut crate::src::threads::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    if cur.is_null() {
        return;
    }
    buf = (*ctxt).buf;
    root = cur;
    parent = (*cur).parent;
    loop {
        match (*cur).type_0 as u32 {
            9 | 13 => {
                xmlDocContentDumpOutput(ctxt, cur as xmlDocPtr);
            }
            14 => {
                xmlDtdDumpOutput(ctxt, cur as xmlDtdPtr);
            }
            11 => {
                if (*cur).parent == parent && !((*cur).children).is_null() {
                    parent = cur;
                    cur = (*cur).children;
                    continue;
                }
            }
            15 => {
                xmlBufDumpElementDecl((*buf).buffer, cur as xmlElementPtr);
            }
            16 => {
                xmlBufDumpAttributeDecl((*buf).buffer, cur as xmlAttributePtr);
            }
            17 => {
                xmlBufDumpEntityDecl((*buf).buffer, cur as xmlEntityPtr);
            }
            1 => {
                if cur != root && (*ctxt).format == 1 as i32
                    && *__xmlIndentTreeOutput() != 0
                {
                    xmlOutputBufferWrite(
                        buf,
                        (*ctxt).indent_size
                            * (if (*ctxt).level > (*ctxt).indent_nr {
                                (*ctxt).indent_nr
                            } else {
                                (*ctxt).level
                            }),
                        ((*ctxt).indent).as_mut_ptr(),
                    );
                }
                if (*cur).parent != parent && !((*cur).children).is_null() {
                    xmlNodeDumpOutputInternal(ctxt, cur);
                } else {
                    xmlOutputBufferWrite(
                        buf,
                        1 as i32,
                        b"<\0" as *const u8 as *const i8,
                    );
                    if !((*cur).ns).is_null() && !((*(*cur).ns).prefix).is_null() {
                        xmlOutputBufferWriteString(
                            buf,
                            (*(*cur).ns).prefix as *const i8,
                        );
                        xmlOutputBufferWrite(
                            buf,
                            1 as i32,
                            b":\0" as *const u8 as *const i8,
                        );
                    }
                    xmlOutputBufferWriteString(buf, (*cur).name as *const i8);
                    if !((*cur).nsDef).is_null() {
                        xmlNsListDumpOutputCtxt(ctxt, (*cur).nsDef);
                    }
                    attr = (*cur).properties;
                    while !attr.is_null() {
                        xmlAttrDumpOutput(ctxt, attr);
                        attr = (*attr).next;
                    }
                    if ((*cur).children).is_null() {
                        if (*ctxt).options & XML_SAVE_NO_EMPTY as i32
                            == 0 as i32
                        {
                            if (*ctxt).format == 2 as i32 {
                                xmlOutputBufferWriteWSNonSig(ctxt, 0 as i32);
                            }
                            xmlOutputBufferWrite(
                                buf,
                                2 as i32,
                                b"/>\0" as *const u8 as *const i8,
                            );
                        } else {
                            if (*ctxt).format == 2 as i32 {
                                xmlOutputBufferWriteWSNonSig(ctxt, 1 as i32);
                            }
                            xmlOutputBufferWrite(
                                buf,
                                3 as i32,
                                b"></\0" as *const u8 as *const i8,
                            );
                            if !((*cur).ns).is_null() && !((*(*cur).ns).prefix).is_null()
                            {
                                xmlOutputBufferWriteString(
                                    buf,
                                    (*(*cur).ns).prefix as *const i8,
                                );
                                xmlOutputBufferWrite(
                                    buf,
                                    1 as i32,
                                    b":\0" as *const u8 as *const i8,
                                );
                            }
                            xmlOutputBufferWriteString(
                                buf,
                                (*cur).name as *const i8,
                            );
                            if (*ctxt).format == 2 as i32 {
                                xmlOutputBufferWriteWSNonSig(ctxt, 0 as i32);
                            }
                            xmlOutputBufferWrite(
                                buf,
                                1 as i32,
                                b">\0" as *const u8 as *const i8,
                            );
                        }
                    } else {
                        if (*ctxt).format == 1 as i32 {
                            tmp = (*cur).children;
                            while !tmp.is_null() {
                                if (*tmp).type_0 as u32
                                    == XML_TEXT_NODE as i32 as u32
                                    || (*tmp).type_0 as u32
                                        == XML_CDATA_SECTION_NODE as i32 as u32
                                    || (*tmp).type_0 as u32
                                        == XML_ENTITY_REF_NODE as i32 as u32
                                {
                                    (*ctxt).format = 0 as i32;
                                    unformattedNode = cur;
                                    break;
                                } else {
                                    tmp = (*tmp).next;
                                }
                            }
                        }
                        if (*ctxt).format == 2 as i32 {
                            xmlOutputBufferWriteWSNonSig(ctxt, 1 as i32);
                        }
                        xmlOutputBufferWrite(
                            buf,
                            1 as i32,
                            b">\0" as *const u8 as *const i8,
                        );
                        if (*ctxt).format == 1 as i32 {
                            xmlOutputBufferWrite(
                                buf,
                                1 as i32,
                                b"\n\0" as *const u8 as *const i8,
                            );
                        }
                        if (*ctxt).level >= 0 as i32 {
                            let fresh48 = &mut ((*ctxt).level);
                            *fresh48 += 1;
                        }
                        parent = cur;
                        cur = (*cur).children;
                        continue;
                    }
                }
            }
            3 => {
                if !((*cur).content).is_null() {
                    if (*cur).name != xmlStringTextNoenc.as_ptr() {
                        xmlOutputBufferWriteEscape(buf, (*cur).content, (*ctxt).escape);
                    } else {
                        xmlOutputBufferWriteString(
                            buf,
                            (*cur).content as *const i8,
                        );
                    }
                }
            }
            7 => {
                if cur != root && (*ctxt).format == 1 as i32
                    && *__xmlIndentTreeOutput() != 0
                {
                    xmlOutputBufferWrite(
                        buf,
                        (*ctxt).indent_size
                            * (if (*ctxt).level > (*ctxt).indent_nr {
                                (*ctxt).indent_nr
                            } else {
                                (*ctxt).level
                            }),
                        ((*ctxt).indent).as_mut_ptr(),
                    );
                }
                if !((*cur).content).is_null() {
                    xmlOutputBufferWrite(
                        buf,
                        2 as i32,
                        b"<?\0" as *const u8 as *const i8,
                    );
                    xmlOutputBufferWriteString(buf, (*cur).name as *const i8);
                    if !((*cur).content).is_null() {
                        if (*ctxt).format == 2 as i32 {
                            xmlOutputBufferWriteWSNonSig(ctxt, 0 as i32);
                        } else {
                            xmlOutputBufferWrite(
                                buf,
                                1 as i32,
                                b" \0" as *const u8 as *const i8,
                            );
                        }
                        xmlOutputBufferWriteString(
                            buf,
                            (*cur).content as *const i8,
                        );
                    }
                    xmlOutputBufferWrite(
                        buf,
                        2 as i32,
                        b"?>\0" as *const u8 as *const i8,
                    );
                } else {
                    xmlOutputBufferWrite(
                        buf,
                        2 as i32,
                        b"<?\0" as *const u8 as *const i8,
                    );
                    xmlOutputBufferWriteString(buf, (*cur).name as *const i8);
                    if (*ctxt).format == 2 as i32 {
                        xmlOutputBufferWriteWSNonSig(ctxt, 0 as i32);
                    }
                    xmlOutputBufferWrite(
                        buf,
                        2 as i32,
                        b"?>\0" as *const u8 as *const i8,
                    );
                }
            }
            8 => {
                if cur != root && (*ctxt).format == 1 as i32
                    && *__xmlIndentTreeOutput() != 0
                {
                    xmlOutputBufferWrite(
                        buf,
                        (*ctxt).indent_size
                            * (if (*ctxt).level > (*ctxt).indent_nr {
                                (*ctxt).indent_nr
                            } else {
                                (*ctxt).level
                            }),
                        ((*ctxt).indent).as_mut_ptr(),
                    );
                }
                if !((*cur).content).is_null() {
                    xmlOutputBufferWrite(
                        buf,
                        4 as i32,
                        b"<!--\0" as *const u8 as *const i8,
                    );
                    xmlOutputBufferWriteString(
                        buf,
                        (*cur).content as *const i8,
                    );
                    xmlOutputBufferWrite(
                        buf,
                        3 as i32,
                        b"-->\0" as *const u8 as *const i8,
                    );
                }
            }
            5 => {
                xmlOutputBufferWrite(
                    buf,
                    1 as i32,
                    b"&\0" as *const u8 as *const i8,
                );
                xmlOutputBufferWriteString(buf, (*cur).name as *const i8);
                xmlOutputBufferWrite(
                    buf,
                    1 as i32,
                    b";\0" as *const u8 as *const i8,
                );
            }
            4 => {
                if ((*cur).content).is_null()
                    || *(*cur).content as i32 == '\u{0}' as i32
                {
                    xmlOutputBufferWrite(
                        buf,
                        12 as i32,
                        b"<![CDATA[]]>\0" as *const u8 as *const i8,
                    );
                } else {
                    end = (*cur).content;
                    start = end;
                    while *end as i32 != '\u{0}' as i32 {
                        if *end as i32 == ']' as i32
                            && *end.offset(1 as i32 as isize) as i32
                                == ']' as i32
                            && *end.offset(2 as i32 as isize) as i32
                                == '>' as i32
                        {
                            end = end.offset(2 as i32 as isize);
                            xmlOutputBufferWrite(
                                buf,
                                9 as i32,
                                b"<![CDATA[\0" as *const u8 as *const i8,
                            );
                            xmlOutputBufferWrite(
                                buf,
                                end.offset_from(start) as i64 as i32,
                                start as *const i8,
                            );
                            xmlOutputBufferWrite(
                                buf,
                                3 as i32,
                                b"]]>\0" as *const u8 as *const i8,
                            );
                            start = end;
                        }
                        end = end.offset(1);
                    }
                    if start != end {
                        xmlOutputBufferWrite(
                            buf,
                            9 as i32,
                            b"<![CDATA[\0" as *const u8 as *const i8,
                        );
                        xmlOutputBufferWriteString(buf, start as *const i8);
                        xmlOutputBufferWrite(
                            buf,
                            3 as i32,
                            b"]]>\0" as *const u8 as *const i8,
                        );
                    }
                }
            }
            2 => {
                xmlAttrDumpOutput(ctxt, cur as xmlAttrPtr);
            }
            18 => {
                xmlNsDumpOutputCtxt(ctxt, cur as xmlNsPtr);
            }
            _ => {}
        }
        loop {
            if cur == root {
                return;
            }
            if (*ctxt).format == 1 as i32
                && (*cur).type_0 as u32
                    != XML_XINCLUDE_START as i32 as u32
                && (*cur).type_0 as u32
                    != XML_XINCLUDE_END as i32 as u32
            {
                xmlOutputBufferWrite(
                    buf,
                    1 as i32,
                    b"\n\0" as *const u8 as *const i8,
                );
            }
            if !((*cur).next).is_null() {
                cur = (*cur).next;
                break;
            } else {
                cur = parent;
                parent = (*cur).parent;
                if (*cur).type_0 as u32
                    == XML_ELEMENT_NODE as i32 as u32
                {
                    if (*ctxt).level > 0 as i32 {
                        let fresh49 = &mut ((*ctxt).level);
                        *fresh49 -= 1;
                    }
                    if *__xmlIndentTreeOutput() != 0
                        && (*ctxt).format == 1 as i32
                    {
                        xmlOutputBufferWrite(
                            buf,
                            (*ctxt).indent_size
                                * (if (*ctxt).level > (*ctxt).indent_nr {
                                    (*ctxt).indent_nr
                                } else {
                                    (*ctxt).level
                                }),
                            ((*ctxt).indent).as_mut_ptr(),
                        );
                    }
                    xmlOutputBufferWrite(
                        buf,
                        2 as i32,
                        b"</\0" as *const u8 as *const i8,
                    );
                    if !((*cur).ns).is_null() && !((*(*cur).ns).prefix).is_null() {
                        xmlOutputBufferWriteString(
                            buf,
                            (*(*cur).ns).prefix as *const i8,
                        );
                        xmlOutputBufferWrite(
                            buf,
                            1 as i32,
                            b":\0" as *const u8 as *const i8,
                        );
                    }
                    xmlOutputBufferWriteString(buf, (*cur).name as *const i8);
                    if (*ctxt).format == 2 as i32 {
                        xmlOutputBufferWriteWSNonSig(ctxt, 0 as i32);
                    }
                    xmlOutputBufferWrite(
                        buf,
                        1 as i32,
                        b">\0" as *const u8 as *const i8,
                    );
                    if cur == unformattedNode {
                        (*ctxt).format = format;
                        unformattedNode = 0 as xmlNodePtr;
                    }
                }
            }
        }
    };
}
unsafe extern "C" fn xmlDocContentDumpOutput<'a1>(
    mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>,
    mut cur: * mut crate::src::threads::_xmlDoc,
) -> i32 {
    let mut dtd: * mut crate::src::threads::_xmlDtd = 0 as *mut xmlDtd;
    let mut is_xhtml: i32 = 0 as i32;
    let mut oldenc: * const u8 = (*cur).encoding;
    let mut oldctxtenc: * const u8 = (*ctxt).encoding;
    let mut encoding: * const u8 = (*ctxt).encoding;
    let mut oldescape: Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32> = (*ctxt).escape;
    let mut oldescapeAttr: Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32> = (*ctxt).escapeAttr;
    let mut buf: * mut crate::src::threads::_xmlOutputBuffer = (*ctxt).buf;
    let mut enc: i32 = XML_CHAR_ENCODING_NONE;
    let mut switched_encoding: i32 = 0 as i32;
    xmlInitParser();
    if (*cur).type_0 as u32
        != XML_HTML_DOCUMENT_NODE as i32 as u32
        && (*cur).type_0 as u32
            != XML_DOCUMENT_NODE as i32 as u32
    {
        return -(1 as i32);
    }
    if !((*ctxt).encoding).is_null() {
        let fresh50 = &mut ((*cur).encoding);
        *fresh50 = (*ctxt).encoding as *mut xmlChar;
    } else if !((*cur).encoding).is_null() {
        encoding = (*cur).encoding;
    }
    if (*cur).type_0 as u32
        == XML_HTML_DOCUMENT_NODE as i32 as u32
        && (*ctxt).options & XML_SAVE_AS_XML as i32 == 0 as i32
        && (*ctxt).options & XML_SAVE_XHTML as i32 == 0 as i32
        || (*ctxt).options & XML_SAVE_AS_HTML as i32 != 0
    {
        if !encoding.is_null() {
            htmlSetMetaEncoding(cur, encoding);
        }
        if encoding.is_null() {
            encoding = htmlGetMetaEncoding(cur);
        }
        if encoding.is_null() {
            encoding = b"HTML\0" as *const u8 as *const i8 as *mut xmlChar;
        }
        if !encoding.is_null() && oldctxtenc.is_null() && ((*buf).encoder).is_null()
            && ((*buf).conv).is_null()
        {
            if xmlSaveSwitchEncoding(ctxt, encoding as *const i8)
                < 0 as i32
            {
                let fresh51 = &mut ((*cur).encoding);
                *fresh51 = oldenc;
                return -(1 as i32);
            }
        }
        if (*ctxt).options & XML_SAVE_FORMAT as i32 != 0 {
            htmlDocContentDumpFormatOutput(
                buf,
                cur,
                encoding as *const i8,
                1 as i32,
            );
        } else {
            htmlDocContentDumpFormatOutput(
                buf,
                cur,
                encoding as *const i8,
                0 as i32,
            );
        }
        if !((*ctxt).encoding).is_null() {
            let fresh52 = &mut ((*cur).encoding);
            *fresh52 = oldenc;
        }
        return 0 as i32;
    } else {
        if (*cur).type_0 as u32
            == XML_DOCUMENT_NODE as i32 as u32
            || (*ctxt).options & XML_SAVE_AS_XML as i32 != 0
            || (*ctxt).options & XML_SAVE_XHTML as i32 != 0
        {
            enc = xmlParseCharEncoding(encoding as *const i8);
            if !encoding.is_null() && oldctxtenc.is_null() && ((*buf).encoder).is_null()
                && ((*buf).conv).is_null()
                && (*ctxt).options & XML_SAVE_NO_DECL as i32 == 0 as i32
            {
                if enc as i32 != XML_CHAR_ENCODING_UTF8 as i32
                    && enc as i32 != XML_CHAR_ENCODING_NONE as i32
                    && enc as i32 != XML_CHAR_ENCODING_ASCII as i32
                {
                    if xmlSaveSwitchEncoding(ctxt, encoding as *const i8)
                        < 0 as i32
                    {
                        let fresh53 = &mut ((*cur).encoding);
                        *fresh53 = oldenc;
                        return -(1 as i32);
                    }
                    switched_encoding = 1 as i32;
                }
                if ((*ctxt).escape
                    ).map(|f| f as usize) == ( Some(
                        xmlEscapeEntities,
                    )).map(|f| f as usize)
                {
                    let fresh54 = &mut ((*ctxt).escape);
                    *fresh54 = None;
                }
                if ((*ctxt).escapeAttr
                    ).map(|f| f as usize) == ( Some(
                        xmlEscapeEntities,
                    )).map(|f| f as usize)
                {
                    let fresh55 = &mut ((*ctxt).escapeAttr);
                    *fresh55 = None;
                }
            }
            if (*ctxt).options & XML_SAVE_NO_DECL as i32 == 0 as i32 {
                xmlOutputBufferWrite(
                    buf,
                    14 as i32,
                    b"<?xml version=\0" as *const u8 as *const i8,
                );
                if !((*cur).version).is_null() {
                    xmlBufWriteQuotedString((*buf).buffer, (*cur).version);
                } else {
                    xmlOutputBufferWrite(
                        buf,
                        5 as i32,
                        b"\"1.0\"\0" as *const u8 as *const i8,
                    );
                }
                if !encoding.is_null() {
                    xmlOutputBufferWrite(
                        buf,
                        10 as i32,
                        b" encoding=\0" as *const u8 as *const i8,
                    );
                    xmlBufWriteQuotedString((*buf).buffer, encoding as *mut xmlChar);
                }
                match (*cur).standalone {
                    0 => {
                        xmlOutputBufferWrite(
                            buf,
                            16 as i32,
                            b" standalone=\"no\"\0" as *const u8 as *const i8,
                        );
                    }
                    1 => {
                        xmlOutputBufferWrite(
                            buf,
                            17 as i32,
                            b" standalone=\"yes\"\0" as *const u8 as *const i8,
                        );
                    }
                    _ => {}
                }
                xmlOutputBufferWrite(
                    buf,
                    3 as i32,
                    b"?>\n\0" as *const u8 as *const i8,
                );
            }
            if (*ctxt).options & XML_SAVE_XHTML as i32 != 0 {
                is_xhtml = 1 as i32;
            }
            if (*ctxt).options & XML_SAVE_NO_XHTML as i32 == 0 as i32 {
                dtd = xmlGetIntSubset(cur as *const xmlDoc);
                if !dtd.is_null() {
                    is_xhtml = xmlIsXHTML((*dtd).SystemID, (*dtd).ExternalID);
                    if is_xhtml < 0 as i32 {
                        is_xhtml = 0 as i32;
                    }
                }
            }
            if !((*cur).children).is_null() {
                let mut child: * mut crate::src::threads::_xmlNode = (*cur).children;
                while !child.is_null() {
                    (*ctxt).level = 0 as i32;
                    if is_xhtml != 0 {
                        xhtmlNodeDumpOutput(ctxt, child);
                    } else {
                        xmlNodeDumpOutputInternal(ctxt, child);
                    }
                    if (*child).type_0 as u32
                        != XML_XINCLUDE_START as i32 as u32
                        && (*child).type_0 as u32
                            != XML_XINCLUDE_END as i32 as u32
                    {
                        xmlOutputBufferWrite(
                            buf,
                            1 as i32,
                            b"\n\0" as *const u8 as *const i8,
                        );
                    }
                    child = (*child).next;
                }
            }
        }
    }
    if switched_encoding != 0 && oldctxtenc.is_null() {
        xmlSaveClearEncoding(ctxt);
        let fresh56 = &mut ((*ctxt).escape);
        *fresh56 = oldescape;
        let fresh57 = &mut ((*ctxt).escapeAttr);
        *fresh57 = oldescapeAttr;
    }
    let fresh58 = &mut ((*cur).encoding);
    *fresh58 = oldenc;
    return 0 as i32;
}
unsafe extern "C" fn xhtmlIsEmpty(mut node: * mut crate::src::threads::_xmlNode) -> i32 {
    if node.is_null() {
        return -(1 as i32);
    }
    if (*node).type_0 as u32 != XML_ELEMENT_NODE as i32 as u32
    {
        return 0 as i32;
    }
    if !((*node).ns).is_null()
        && xmlStrEqual(
            (*(*node).ns).href,
            b"http://www.w3.org/1999/xhtml\0" as *const u8 as *const i8
                as *mut xmlChar,
        ) == 0
    {
        return 0 as i32;
    }
    if !((*node).children).is_null() {
        return 0 as i32;
    }
    match *((*node).name).offset(0 as i32 as isize) as i32 {
        97 => {
            if xmlStrEqual(
                (*node).name,
                b"area\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        98 => {
            if xmlStrEqual(
                (*node).name,
                b"br\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                return 1 as i32;
            }
            if xmlStrEqual(
                (*node).name,
                b"base\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                return 1 as i32;
            }
            if xmlStrEqual(
                (*node).name,
                b"basefont\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        99 => {
            if xmlStrEqual(
                (*node).name,
                b"col\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        102 => {
            if xmlStrEqual(
                (*node).name,
                b"frame\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        104 => {
            if xmlStrEqual(
                (*node).name,
                b"hr\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        105 => {
            if xmlStrEqual(
                (*node).name,
                b"img\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                return 1 as i32;
            }
            if xmlStrEqual(
                (*node).name,
                b"input\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                return 1 as i32;
            }
            if xmlStrEqual(
                (*node).name,
                b"isindex\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        108 => {
            if xmlStrEqual(
                (*node).name,
                b"link\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        109 => {
            if xmlStrEqual(
                (*node).name,
                b"meta\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        112 => {
            if xmlStrEqual(
                (*node).name,
                b"param\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        _ => {}
    }
    return 0 as i32;
}
unsafe extern "C" fn xhtmlAttrListDumpOutput<'a1>(
    mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>,
    mut cur: * mut crate::src::threads::_xmlAttr,
) {
    let mut xml_lang: * mut crate::src::threads::_xmlAttr = 0 as xmlAttrPtr;
    let mut lang: * mut crate::src::threads::_xmlAttr = 0 as xmlAttrPtr;
    let mut name: * mut crate::src::threads::_xmlAttr = 0 as xmlAttrPtr;
    let mut id: * mut crate::src::threads::_xmlAttr = 0 as xmlAttrPtr;
    let mut parent: * mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut buf: * mut crate::src::threads::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    if cur.is_null() {
        return;
    }
    buf = (*ctxt).buf;
    parent = (*cur).parent;
    while !cur.is_null() {
        if ((*cur).ns).is_null()
            && xmlStrEqual(
                (*cur).name,
                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
        {
            id = cur;
        } else if ((*cur).ns).is_null()
                && xmlStrEqual(
                    (*cur).name,
                    b"name\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
            {
            name = cur;
        } else if ((*cur).ns).is_null()
                && xmlStrEqual(
                    (*cur).name,
                    b"lang\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
            {
            lang = cur;
        } else if !((*cur).ns).is_null()
                && xmlStrEqual(
                    (*cur).name,
                    b"lang\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
                && xmlStrEqual(
                    (*(*cur).ns).prefix,
                    b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
            {
            xml_lang = cur;
        } else if ((*cur).ns).is_null()
                && (((*cur).children).is_null() || ((*(*cur).children).content).is_null()
                    || *((*(*cur).children).content).offset(0 as i32 as isize)
                        as i32 == 0 as i32)
                && htmlIsBooleanAttr((*cur).name) != 0
            {
            if !((*cur).children).is_null() {
                xmlFreeNode((*cur).children);
            }
            let fresh59 = &mut ((*cur).children);
            *fresh59 = xmlNewDocText((*cur).doc, (*cur).name);
            if !((*cur).children).is_null() {
                let fresh60 = &mut ((*(*cur).children).parent);
                *fresh60 = cur as xmlNodePtr;
            }
        }
        xmlAttrDumpOutput(ctxt, cur);
        cur = (*cur).next;
    }
    if !name.is_null() && id.is_null() {
        if !parent.is_null() && !((*parent).name).is_null()
            && (xmlStrEqual(
                (*parent).name,
                b"a\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
                || xmlStrEqual(
                    (*parent).name,
                    b"p\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
                || xmlStrEqual(
                    (*parent).name,
                    b"div\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
                || xmlStrEqual(
                    (*parent).name,
                    b"img\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
                || xmlStrEqual(
                    (*parent).name,
                    b"map\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
                || xmlStrEqual(
                    (*parent).name,
                    b"applet\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
                || xmlStrEqual(
                    (*parent).name,
                    b"form\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
                || xmlStrEqual(
                    (*parent).name,
                    b"frame\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
                || xmlStrEqual(
                    (*parent).name,
                    b"iframe\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0)
        {
            xmlOutputBufferWrite(
                buf,
                5 as i32,
                b" id=\"\0" as *const u8 as *const i8,
            );
            xmlAttrSerializeContent(buf, name);
            xmlOutputBufferWrite(
                buf,
                1 as i32,
                b"\"\0" as *const u8 as *const i8,
            );
        }
    }
    if !lang.is_null() && xml_lang.is_null() {
        xmlOutputBufferWrite(
            buf,
            11 as i32,
            b" xml:lang=\"\0" as *const u8 as *const i8,
        );
        xmlAttrSerializeContent(buf, lang);
        xmlOutputBufferWrite(
            buf,
            1 as i32,
            b"\"\0" as *const u8 as *const i8,
        );
    } else if !xml_lang.is_null() && lang.is_null() {
        xmlOutputBufferWrite(
            buf,
            7 as i32,
            b" lang=\"\0" as *const u8 as *const i8,
        );
        xmlAttrSerializeContent(buf, xml_lang);
        xmlOutputBufferWrite(
            buf,
            1 as i32,
            b"\"\0" as *const u8 as *const i8,
        );
    }
}
unsafe extern "C" fn xhtmlNodeDumpOutput<'a1>(mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>, mut cur: * mut crate::src::threads::_xmlNode) {
    let mut format: i32 = (*ctxt).format;
    let mut addmeta: i32 = 0;
    let mut tmp: * mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut root: * mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut unformattedNode: * mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut start: * mut u8 = 0 as *mut xmlChar;
    let mut end: * mut u8 = 0 as *mut xmlChar;
    let mut buf: * mut crate::src::threads::_xmlOutputBuffer = (*ctxt).buf;
    if cur.is_null() {
        return;
    }
    root = cur;
    loop {
        match (*cur).type_0 as u32 {
            9 | 13 => {
                xmlDocContentDumpOutput(ctxt, cur as xmlDocPtr);
            }
            18 => {
                xmlNsDumpOutputCtxt(ctxt, cur as xmlNsPtr);
            }
            14 => {
                xmlDtdDumpOutput(ctxt, cur as xmlDtdPtr);
            }
            11 => {
                if !((*cur).children).is_null() {
                    cur = (*cur).children;
                    continue;
                }
            }
            15 => {
                xmlBufDumpElementDecl((*buf).buffer, cur as xmlElementPtr);
            }
            16 => {
                xmlBufDumpAttributeDecl((*buf).buffer, cur as xmlAttributePtr);
            }
            17 => {
                xmlBufDumpEntityDecl((*buf).buffer, cur as xmlEntityPtr);
            }
            1 => {
                addmeta = 0 as i32;
                if cur != root && (*ctxt).format == 1 as i32
                    && *__xmlIndentTreeOutput() != 0
                {
                    xmlOutputBufferWrite(
                        buf,
                        (*ctxt).indent_size
                            * (if (*ctxt).level > (*ctxt).indent_nr {
                                (*ctxt).indent_nr
                            } else {
                                (*ctxt).level
                            }),
                        ((*ctxt).indent).as_mut_ptr(),
                    );
                }
                xmlOutputBufferWrite(
                    buf,
                    1 as i32,
                    b"<\0" as *const u8 as *const i8,
                );
                if !((*cur).ns).is_null() && !((*(*cur).ns).prefix).is_null() {
                    xmlOutputBufferWriteString(
                        buf,
                        (*(*cur).ns).prefix as *const i8,
                    );
                    xmlOutputBufferWrite(
                        buf,
                        1 as i32,
                        b":\0" as *const u8 as *const i8,
                    );
                }
                xmlOutputBufferWriteString(buf, (*cur).name as *const i8);
                if !((*cur).nsDef).is_null() {
                    xmlNsListDumpOutputCtxt(ctxt, (*cur).nsDef);
                }
                if xmlStrEqual(
                    (*cur).name,
                    b"html\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0 && ((*cur).ns).is_null() && ((*cur).nsDef).is_null()
                {
                    xmlOutputBufferWriteString(
                        buf,
                        b" xmlns=\"http://www.w3.org/1999/xhtml\"\0" as *const u8
                            as *const i8,
                    );
                }
                if !((*cur).properties).is_null() {
                    xhtmlAttrListDumpOutput(ctxt, (*cur).properties);
                }
                if !((*cur).parent).is_null()
                    && (*(*cur).parent).parent == (*cur).doc as xmlNodePtr
                    && xmlStrEqual(
                        (*cur).name,
                        b"head\0" as *const u8 as *const i8 as *mut xmlChar,
                    ) != 0
                    && xmlStrEqual(
                        (*(*cur).parent).name,
                        b"html\0" as *const u8 as *const i8 as *mut xmlChar,
                    ) != 0
                {
                    tmp = (*cur).children;
                    while !tmp.is_null() {
                        if xmlStrEqual(
                            (*tmp).name,
                            b"meta\0" as *const u8 as *const i8 as *mut xmlChar,
                        ) != 0
                        {
                            let mut httpequiv: * mut u8 = 0 as *mut xmlChar;
                            httpequiv = xmlGetProp(
                                tmp as *const xmlNode,
                                b"http-equiv\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                            );
                            if !httpequiv.is_null() {
                                if xmlStrcasecmp(
                                    httpequiv,
                                    b"Content-Type\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                ) == 0 as i32
                                {
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(httpequiv as *mut libc::c_void);
                                    break;
                                } else {
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(httpequiv as *mut libc::c_void);
                                }
                            }
                        }
                        tmp = (*tmp).next;
                    }
                    if tmp.is_null() {
                        addmeta = 1 as i32;
                    }
                }
                if ((*cur).children).is_null() {
                    if (((*cur).ns).is_null() || ((*(*cur).ns).prefix).is_null())
                        && (xhtmlIsEmpty(cur) == 1 as i32
                            && addmeta == 0 as i32)
                    {
                        xmlOutputBufferWrite(
                            buf,
                            3 as i32,
                            b" />\0" as *const u8 as *const i8,
                        );
                    } else {
                        if addmeta == 1 as i32 {
                            xmlOutputBufferWrite(
                                buf,
                                1 as i32,
                                b">\0" as *const u8 as *const i8,
                            );
                            if (*ctxt).format == 1 as i32 {
                                xmlOutputBufferWrite(
                                    buf,
                                    1 as i32,
                                    b"\n\0" as *const u8 as *const i8,
                                );
                                if *__xmlIndentTreeOutput() != 0 {
                                    xmlOutputBufferWrite(
                                        buf,
                                        (*ctxt).indent_size
                                            * (if (*ctxt).level + 1 as i32 > (*ctxt).indent_nr {
                                                (*ctxt).indent_nr
                                            } else {
                                                (*ctxt).level + 1 as i32
                                            }),
                                        ((*ctxt).indent).as_mut_ptr(),
                                    );
                                }
                            }
                            xmlOutputBufferWriteString(
                                buf,
                                b"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=\0"
                                    as *const u8 as *const i8,
                            );
                            if !((*ctxt).encoding).is_null() {
                                xmlOutputBufferWriteString(
                                    buf,
                                    (*ctxt).encoding as *const i8,
                                );
                            } else {
                                xmlOutputBufferWrite(
                                    buf,
                                    5 as i32,
                                    b"UTF-8\0" as *const u8 as *const i8,
                                );
                            }
                            xmlOutputBufferWrite(
                                buf,
                                4 as i32,
                                b"\" />\0" as *const u8 as *const i8,
                            );
                            if (*ctxt).format == 1 as i32 {
                                xmlOutputBufferWrite(
                                    buf,
                                    1 as i32,
                                    b"\n\0" as *const u8 as *const i8,
                                );
                            }
                        } else {
                            xmlOutputBufferWrite(
                                buf,
                                1 as i32,
                                b">\0" as *const u8 as *const i8,
                            );
                        }
                        xmlOutputBufferWrite(
                            buf,
                            2 as i32,
                            b"</\0" as *const u8 as *const i8,
                        );
                        if !((*cur).ns).is_null() && !((*(*cur).ns).prefix).is_null() {
                            xmlOutputBufferWriteString(
                                buf,
                                (*(*cur).ns).prefix as *const i8,
                            );
                            xmlOutputBufferWrite(
                                buf,
                                1 as i32,
                                b":\0" as *const u8 as *const i8,
                            );
                        }
                        xmlOutputBufferWriteString(
                            buf,
                            (*cur).name as *const i8,
                        );
                        xmlOutputBufferWrite(
                            buf,
                            1 as i32,
                            b">\0" as *const u8 as *const i8,
                        );
                    }
                } else {
                    xmlOutputBufferWrite(
                        buf,
                        1 as i32,
                        b">\0" as *const u8 as *const i8,
                    );
                    if addmeta == 1 as i32 {
                        if (*ctxt).format == 1 as i32 {
                            xmlOutputBufferWrite(
                                buf,
                                1 as i32,
                                b"\n\0" as *const u8 as *const i8,
                            );
                            if *__xmlIndentTreeOutput() != 0 {
                                xmlOutputBufferWrite(
                                    buf,
                                    (*ctxt).indent_size
                                        * (if (*ctxt).level + 1 as i32 > (*ctxt).indent_nr {
                                            (*ctxt).indent_nr
                                        } else {
                                            (*ctxt).level + 1 as i32
                                        }),
                                    ((*ctxt).indent).as_mut_ptr(),
                                );
                            }
                        }
                        xmlOutputBufferWriteString(
                            buf,
                            b"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=\0"
                                as *const u8 as *const i8,
                        );
                        if !((*ctxt).encoding).is_null() {
                            xmlOutputBufferWriteString(
                                buf,
                                (*ctxt).encoding as *const i8,
                            );
                        } else {
                            xmlOutputBufferWrite(
                                buf,
                                5 as i32,
                                b"UTF-8\0" as *const u8 as *const i8,
                            );
                        }
                        xmlOutputBufferWrite(
                            buf,
                            4 as i32,
                            b"\" />\0" as *const u8 as *const i8,
                        );
                    }
                    if (*ctxt).format == 1 as i32 {
                        tmp = (*cur).children;
                        while !tmp.is_null() {
                            if (*tmp).type_0 as u32
                                == XML_TEXT_NODE as i32 as u32
                                || (*tmp).type_0 as u32
                                    == XML_ENTITY_REF_NODE as i32 as u32
                            {
                                unformattedNode = cur;
                                (*ctxt).format = 0 as i32;
                                break;
                            } else {
                                tmp = (*tmp).next;
                            }
                        }
                    }
                    if (*ctxt).format == 1 as i32 {
                        xmlOutputBufferWrite(
                            buf,
                            1 as i32,
                            b"\n\0" as *const u8 as *const i8,
                        );
                    }
                    if (*ctxt).level >= 0 as i32 {
                        let fresh61 = &mut ((*ctxt).level);
                        *fresh61 += 1;
                    }
                    cur = (*cur).children;
                    continue;
                }
            }
            3 => {
                if !((*cur).content).is_null() {
                    if (*cur).name == xmlStringText.as_ptr()
                        || (*cur).name != xmlStringTextNoenc.as_ptr()
                    {
                        xmlOutputBufferWriteEscape(buf, (*cur).content, (*ctxt).escape);
                    } else {
                        xmlOutputBufferWriteString(
                            buf,
                            (*cur).content as *const i8,
                        );
                    }
                }
            }
            7 => {
                if !((*cur).content).is_null() {
                    xmlOutputBufferWrite(
                        buf,
                        2 as i32,
                        b"<?\0" as *const u8 as *const i8,
                    );
                    xmlOutputBufferWriteString(buf, (*cur).name as *const i8);
                    if !((*cur).content).is_null() {
                        xmlOutputBufferWrite(
                            buf,
                            1 as i32,
                            b" \0" as *const u8 as *const i8,
                        );
                        xmlOutputBufferWriteString(
                            buf,
                            (*cur).content as *const i8,
                        );
                    }
                    xmlOutputBufferWrite(
                        buf,
                        2 as i32,
                        b"?>\0" as *const u8 as *const i8,
                    );
                } else {
                    xmlOutputBufferWrite(
                        buf,
                        2 as i32,
                        b"<?\0" as *const u8 as *const i8,
                    );
                    xmlOutputBufferWriteString(buf, (*cur).name as *const i8);
                    xmlOutputBufferWrite(
                        buf,
                        2 as i32,
                        b"?>\0" as *const u8 as *const i8,
                    );
                }
            }
            8 => {
                if !((*cur).content).is_null() {
                    xmlOutputBufferWrite(
                        buf,
                        4 as i32,
                        b"<!--\0" as *const u8 as *const i8,
                    );
                    xmlOutputBufferWriteString(
                        buf,
                        (*cur).content as *const i8,
                    );
                    xmlOutputBufferWrite(
                        buf,
                        3 as i32,
                        b"-->\0" as *const u8 as *const i8,
                    );
                }
            }
            5 => {
                xmlOutputBufferWrite(
                    buf,
                    1 as i32,
                    b"&\0" as *const u8 as *const i8,
                );
                xmlOutputBufferWriteString(buf, (*cur).name as *const i8);
                xmlOutputBufferWrite(
                    buf,
                    1 as i32,
                    b";\0" as *const u8 as *const i8,
                );
            }
            4 => {
                if ((*cur).content).is_null()
                    || *(*cur).content as i32 == '\u{0}' as i32
                {
                    xmlOutputBufferWrite(
                        buf,
                        12 as i32,
                        b"<![CDATA[]]>\0" as *const u8 as *const i8,
                    );
                } else {
                    end = (*cur).content;
                    start = end;
                    while *end as i32 != '\u{0}' as i32 {
                        if *end as i32 == ']' as i32
                            && *end.offset(1 as i32 as isize) as i32
                                == ']' as i32
                            && *end.offset(2 as i32 as isize) as i32
                                == '>' as i32
                        {
                            end = end.offset(2 as i32 as isize);
                            xmlOutputBufferWrite(
                                buf,
                                9 as i32,
                                b"<![CDATA[\0" as *const u8 as *const i8,
                            );
                            xmlOutputBufferWrite(
                                buf,
                                end.offset_from(start) as i64 as i32,
                                start as *const i8,
                            );
                            xmlOutputBufferWrite(
                                buf,
                                3 as i32,
                                b"]]>\0" as *const u8 as *const i8,
                            );
                            start = end;
                        }
                        end = end.offset(1);
                    }
                    if start != end {
                        xmlOutputBufferWrite(
                            buf,
                            9 as i32,
                            b"<![CDATA[\0" as *const u8 as *const i8,
                        );
                        xmlOutputBufferWriteString(buf, start as *const i8);
                        xmlOutputBufferWrite(
                            buf,
                            3 as i32,
                            b"]]>\0" as *const u8 as *const i8,
                        );
                    }
                }
            }
            2 => {
                xmlAttrDumpOutput(ctxt, cur as xmlAttrPtr);
            }
            _ => {}
        }
        loop {
            if cur == root {
                return;
            }
            if (*ctxt).format == 1 as i32 {
                xmlOutputBufferWrite(
                    buf,
                    1 as i32,
                    b"\n\0" as *const u8 as *const i8,
                );
            }
            if !((*cur).next).is_null() {
                cur = (*cur).next;
                break;
            } else {
                if ((*cur).parent).is_null() {
                    return;
                }
                cur = (*cur).parent;
                if (*cur).type_0 as u32
                    == XML_ELEMENT_NODE as i32 as u32
                {
                    if (*ctxt).level > 0 as i32 {
                        let fresh62 = &mut ((*ctxt).level);
                        *fresh62 -= 1;
                    }
                    if *__xmlIndentTreeOutput() != 0
                        && (*ctxt).format == 1 as i32
                    {
                        xmlOutputBufferWrite(
                            buf,
                            (*ctxt).indent_size
                                * (if (*ctxt).level > (*ctxt).indent_nr {
                                    (*ctxt).indent_nr
                                } else {
                                    (*ctxt).level
                                }),
                            ((*ctxt).indent).as_mut_ptr(),
                        );
                    }
                    xmlOutputBufferWrite(
                        buf,
                        2 as i32,
                        b"</\0" as *const u8 as *const i8,
                    );
                    if !((*cur).ns).is_null() && !((*(*cur).ns).prefix).is_null() {
                        xmlOutputBufferWriteString(
                            buf,
                            (*(*cur).ns).prefix as *const i8,
                        );
                        xmlOutputBufferWrite(
                            buf,
                            1 as i32,
                            b":\0" as *const u8 as *const i8,
                        );
                    }
                    xmlOutputBufferWriteString(buf, (*cur).name as *const i8);
                    xmlOutputBufferWrite(
                        buf,
                        1 as i32,
                        b">\0" as *const u8 as *const i8,
                    );
                    if cur == unformattedNode {
                        (*ctxt).format = format;
                        unformattedNode = 0 as xmlNodePtr;
                    }
                }
            }
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveToFd<'a1>(
    mut fd: i32,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::xmlsave::_xmlSaveCtxt<'a1> {
    let mut ret: * mut crate::src::xmlsave::_xmlSaveCtxt<'_> = 0 as *mut xmlSaveCtxt;
    ret = xmlNewSaveCtxt(encoding, options);
    if ret.is_null() {
        return 0 as xmlSaveCtxtPtr;
    }
    let fresh63 = &mut ((*ret).buf);
    *fresh63 = xmlOutputBufferCreateFd(fd, (*ret).handler);
    if ((*ret).buf).is_null() {
        xmlCharEncCloseFunc((*ret).handler);
        xmlFreeSaveCtxt(ret);
        return 0 as xmlSaveCtxtPtr;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveToFilename<'a1>(
    mut filename: * const i8,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::xmlsave::_xmlSaveCtxt<'a1> {
    let mut ret: * mut crate::src::xmlsave::_xmlSaveCtxt<'_> = 0 as *mut xmlSaveCtxt;
    let mut compression: i32 = 0 as i32;
    ret = xmlNewSaveCtxt(encoding, options);
    if ret.is_null() {
        return 0 as xmlSaveCtxtPtr;
    }
    let fresh64 = &mut ((*ret).buf);
    *fresh64 = xmlOutputBufferCreateFilename(filename, (*ret).handler, compression);
    if ((*ret).buf).is_null() {
        xmlCharEncCloseFunc((*ret).handler);
        xmlFreeSaveCtxt(ret);
        return 0 as xmlSaveCtxtPtr;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveToBuffer<'a1>(
    mut buffer: * mut crate::src::tree::_xmlBuffer,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::xmlsave::_xmlSaveCtxt<'a1> {
    let mut ret: * mut crate::src::xmlsave::_xmlSaveCtxt<'_> = 0 as *mut xmlSaveCtxt;
    ret = xmlNewSaveCtxt(encoding, options);
    if ret.is_null() {
        return 0 as xmlSaveCtxtPtr;
    }
    let fresh65 = &mut ((*ret).buf);
    *fresh65 = xmlOutputBufferCreateBuffer(buffer, (*ret).handler);
    if ((*ret).buf).is_null() {
        xmlCharEncCloseFunc((*ret).handler);
        xmlFreeSaveCtxt(ret);
        return 0 as xmlSaveCtxtPtr;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveToIO<'a1>(
    mut iowrite: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,_: i32,) -> i32>,
    mut ioclose: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>,
    mut ioctx: * mut core::ffi::c_void,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::xmlsave::_xmlSaveCtxt<'a1> {
    let mut ret: * mut crate::src::xmlsave::_xmlSaveCtxt<'_> = 0 as *mut xmlSaveCtxt;
    ret = xmlNewSaveCtxt(encoding, options);
    if ret.is_null() {
        return 0 as xmlSaveCtxtPtr;
    }
    let fresh66 = &mut ((*ret).buf);
    *fresh66 = xmlOutputBufferCreateIO(iowrite, ioclose, ioctx, (*ret).handler);
    if ((*ret).buf).is_null() {
        xmlCharEncCloseFunc((*ret).handler);
        xmlFreeSaveCtxt(ret);
        return 0 as xmlSaveCtxtPtr;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveDoc<'a1>(
    mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>,
    mut doc: * mut crate::src::threads::_xmlDoc,
) -> i64 {
    let mut ret: i64 = 0 as i32 as i64;
    if ctxt.is_null() || doc.is_null() {
        return -(1 as i32) as i64;
    }
    if xmlDocContentDumpOutput(ctxt, doc) < 0 as i32 {
        return -(1 as i32) as i64;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveTree<'a1>(
    mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>,
    mut cur: * mut crate::src::threads::_xmlNode,
) -> i64 {
    let mut ret: i64 = 0 as i32 as i64;
    if ctxt.is_null() || cur.is_null() {
        return -(1 as i32) as i64;
    }
    if (*ctxt).options & XML_SAVE_XHTML as i32 != 0 {
        xhtmlNodeDumpOutput(ctxt, cur);
        return ret;
    }
    if (*cur).type_0 as u32 != XML_NAMESPACE_DECL as i32 as u32
        && !((*cur).doc).is_null()
        && (*(*cur).doc).type_0 as u32
            == XML_HTML_DOCUMENT_NODE as i32 as u32
        && (*ctxt).options & XML_SAVE_AS_XML as i32 == 0 as i32
        || (*ctxt).options & XML_SAVE_AS_HTML as i32 != 0
    {
        htmlNodeDumpOutputInternal(ctxt, cur);
        return ret;
    }
    xmlNodeDumpOutputInternal(ctxt, cur);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveFlush<'a1>(mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>) -> i32 {
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if ((*ctxt).buf).is_null() {
        return -(1 as i32);
    }
    return xmlOutputBufferFlush((*ctxt).buf);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveClose<'a1>(mut ctxt: * mut crate::src::xmlsave::_xmlSaveCtxt<'a1>) -> i32 {
    let mut ret: i32 = 0;
    if ctxt.is_null() {
        return -(1 as i32);
    }
    ret = xmlSaveFlush(ctxt);
    xmlFreeSaveCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveSetEscape<'a1, 'a2>(
    mut ctxt: Option<&'a1 mut crate::src::xmlsave::_xmlSaveCtxt<'a2>>,
    mut escape: Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>,
) -> i32 {
    if borrow(& ctxt).is_none() {
        return -(1 as i32);
    }
    let fresh67 = &mut ((*(borrow_mut(&mut ctxt)).unwrap()).escape);
    *fresh67 = escape;
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveSetAttrEscape<'a1, 'a2>(
    mut ctxt: Option<&'a1 mut crate::src::xmlsave::_xmlSaveCtxt<'a2>>,
    mut escape: Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>,
) -> i32 {
    if borrow(& ctxt).is_none() {
        return -(1 as i32);
    }
    let fresh68 = &mut ((*(borrow_mut(&mut ctxt)).unwrap()).escapeAttr);
    *fresh68 = escape;
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufAttrSerializeTxtContent(
    mut buf: * mut crate::src::xmlstring::_xmlBuf,
    mut doc: * mut crate::src::threads::_xmlDoc,
    mut attr: * mut crate::src::threads::_xmlAttr,
    mut string: * const u8,
) {
    let mut base: * mut u8 = 0 as *mut xmlChar;
    let mut cur: * mut u8 = 0 as *mut xmlChar;
    if string.is_null() {
        return;
    }
    cur = string as *mut xmlChar;
    base = cur;
    while *cur as i32 != 0 as i32 {
        if *cur as i32 == '\n' as i32 {
            if base != cur {
                xmlBufAdd(
                    buf,
                    base,
                    cur.offset_from(base) as i64 as i32,
                );
            }
            xmlBufAdd(
                buf,
                b"&#10;\0" as *const u8 as *const i8 as *mut xmlChar,
                5 as i32,
            );
            cur = cur.offset(1);
            base = cur;
        } else if *cur as i32 == '\r' as i32 {
            if base != cur {
                xmlBufAdd(
                    buf,
                    base,
                    cur.offset_from(base) as i64 as i32,
                );
            }
            xmlBufAdd(
                buf,
                b"&#13;\0" as *const u8 as *const i8 as *mut xmlChar,
                5 as i32,
            );
            cur = cur.offset(1);
            base = cur;
        } else if *cur as i32 == '\t' as i32 {
            if base != cur {
                xmlBufAdd(
                    buf,
                    base,
                    cur.offset_from(base) as i64 as i32,
                );
            }
            xmlBufAdd(
                buf,
                b"&#9;\0" as *const u8 as *const i8 as *mut xmlChar,
                4 as i32,
            );
            cur = cur.offset(1);
            base = cur;
        } else if *cur as i32 == '"' as i32 {
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
        } else if *cur as i32 == '<' as i32 {
            if base != cur {
                xmlBufAdd(
                    buf,
                    base,
                    cur.offset_from(base) as i64 as i32,
                );
            }
            xmlBufAdd(
                buf,
                b"&lt;\0" as *const u8 as *const i8 as *mut xmlChar,
                4 as i32,
            );
            cur = cur.offset(1);
            base = cur;
        } else if *cur as i32 == '>' as i32 {
            if base != cur {
                xmlBufAdd(
                    buf,
                    base,
                    cur.offset_from(base) as i64 as i32,
                );
            }
            xmlBufAdd(
                buf,
                b"&gt;\0" as *const u8 as *const i8 as *mut xmlChar,
                4 as i32,
            );
            cur = cur.offset(1);
            base = cur;
        } else if *cur as i32 == '&' as i32 {
            if base != cur {
                xmlBufAdd(
                    buf,
                    base,
                    cur.offset_from(base) as i64 as i32,
                );
            }
            xmlBufAdd(
                buf,
                b"&amp;\0" as *const u8 as *const i8 as *mut xmlChar,
                5 as i32,
            );
            cur = cur.offset(1);
            base = cur;
        } else if *cur as i32 >= 0x80 as i32
                && *cur.offset(1 as i32 as isize) as i32
                    != 0 as i32 && (doc.is_null() || ((*doc).encoding).is_null())
            {
            let mut tmp: [u8; 12] = [0; 12];
            let mut val: i32 = 0 as i32;
            let mut l: i32 = 1 as i32;
            if base != cur {
                xmlBufAdd(
                    buf,
                    base,
                    cur.offset_from(base) as i64 as i32,
                );
            }
            if (*cur as i32) < 0xc0 as i32 {
                xmlSaveErr(
                    XML_SAVE_NOT_UTF8 as i32,
                    attr as xmlNodePtr,
                    0 as *const i8,
                );
                xmlSerializeHexCharRef(tmp.as_mut_ptr(), *cur as i32);
                xmlBufAdd(buf, tmp.as_mut_ptr() as *mut xmlChar, -(1 as i32));
                cur = cur.offset(1);
                base = cur;
            } else {
                if (*cur as i32) < 0xe0 as i32 {
                    val = *cur.offset(0 as i32 as isize) as i32
                        & 0x1f as i32;
                    val <<= 6 as i32;
                    val
                        |= *cur.offset(1 as i32 as isize) as i32
                            & 0x3f as i32;
                    l = 2 as i32;
                } else if (*cur as i32) < 0xf0 as i32
                        && *cur.offset(2 as i32 as isize) as i32
                            != 0 as i32
                    {
                    val = *cur.offset(0 as i32 as isize) as i32
                        & 0xf as i32;
                    val <<= 6 as i32;
                    val
                        |= *cur.offset(1 as i32 as isize) as i32
                            & 0x3f as i32;
                    val <<= 6 as i32;
                    val
                        |= *cur.offset(2 as i32 as isize) as i32
                            & 0x3f as i32;
                    l = 3 as i32;
                } else if (*cur as i32) < 0xf8 as i32
                        && *cur.offset(2 as i32 as isize) as i32
                            != 0 as i32
                        && *cur.offset(3 as i32 as isize) as i32
                            != 0 as i32
                    {
                    val = *cur.offset(0 as i32 as isize) as i32
                        & 0x7 as i32;
                    val <<= 6 as i32;
                    val
                        |= *cur.offset(1 as i32 as isize) as i32
                            & 0x3f as i32;
                    val <<= 6 as i32;
                    val
                        |= *cur.offset(2 as i32 as isize) as i32
                            & 0x3f as i32;
                    val <<= 6 as i32;
                    val
                        |= *cur.offset(3 as i32 as isize) as i32
                            & 0x3f as i32;
                    l = 4 as i32;
                }
                if l == 1 as i32
                    || (if val < 0x100 as i32 {
                        (0x9 as i32 <= val && val <= 0xa as i32
                            || val == 0xd as i32 || 0x20 as i32 <= val)
                            as i32
                    } else {
                        (0x100 as i32 <= val && val <= 0xd7ff as i32
                            || 0xe000 as i32 <= val
                                && val <= 0xfffd as i32
                            || 0x10000 as i32 <= val
                                && val <= 0x10ffff as i32) as i32
                    }) == 0
                {
                    xmlSaveErr(
                        XML_SAVE_CHAR_INVALID as i32,
                        attr as xmlNodePtr,
                        0 as *const i8,
                    );
                    xmlSerializeHexCharRef(tmp.as_mut_ptr(), *cur as i32);
                    xmlBufAdd(
                        buf,
                        tmp.as_mut_ptr() as *mut xmlChar,
                        -(1 as i32),
                    );
                    cur = cur.offset(1);
                    base = cur;
                } else {
                    xmlSerializeHexCharRef(tmp.as_mut_ptr(), val);
                    xmlBufAdd(
                        buf,
                        tmp.as_mut_ptr() as *mut xmlChar,
                        -(1 as i32),
                    );
                    cur = cur.offset(l as isize);
                    base = cur;
                }
            }
        } else {
            cur = cur.offset(1);
        }
    }
    if base != cur {
        xmlBufAdd(buf, base, cur.offset_from(base) as i64 as i32);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlAttrSerializeTxtContent(
    mut buf: * mut crate::src::tree::_xmlBuffer,
    mut doc: * mut crate::src::threads::_xmlDoc,
    mut attr: * mut crate::src::threads::_xmlAttr,
    mut string: * const u8,
) {
    let mut buffer: * mut crate::src::xmlstring::_xmlBuf = 0 as *mut xmlBuf;
    if buf.is_null() || string.is_null() {
        return;
    }
    buffer = xmlBufFromBuffer(buf);
    if buffer.is_null() {
        return;
    }
    xmlBufAttrSerializeTxtContent(buffer, doc, attr, string);
    xmlBufBackToBuffer(buffer);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeDump(
    mut buf: * mut crate::src::tree::_xmlBuffer,
    mut doc: * mut crate::src::threads::_xmlDoc,
    mut cur: * mut crate::src::threads::_xmlNode,
    mut level: i32,
    mut format: i32,
) -> i32 {
    let mut buffer: * mut crate::src::xmlstring::_xmlBuf = 0 as *mut xmlBuf;
    let mut ret: u64 = 0;
    if buf.is_null() || cur.is_null() {
        return -(1 as i32);
    }
    buffer = xmlBufFromBuffer(buf);
    if buffer.is_null() {
        return -(1 as i32);
    }
    ret = xmlBufNodeDump(buffer, doc, cur, level, format);
    xmlBufBackToBuffer(buffer);
    if ret > 2147483647 as i32 as u64 {
        return -(1 as i32);
    }
    return ret as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufNodeDump(
    mut buf: * mut crate::src::xmlstring::_xmlBuf,
    mut doc: * mut crate::src::threads::_xmlDoc,
    mut cur: * mut crate::src::threads::_xmlNode,
    mut level: i32,
    mut format: i32,
) -> u64 {
    let mut use_0: u64 = 0;
    let mut ret: i32 = 0;
    let mut outbuf: * mut crate::src::threads::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    let mut oldalloc: i32 = 0;
    xmlInitParser();
    if cur.is_null() {
        return -(1 as i32) as size_t;
    }
    if buf.is_null() {
        return -(1 as i32) as size_t;
    }
    outbuf = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlOutputBuffer>() as u64)
        as xmlOutputBufferPtr;
    if outbuf.is_null() {
        xmlSaveErrMemory(b"creating buffer\0" as *const u8 as *const i8);
        return -(1 as i32) as size_t;
    }
    memset(
        outbuf as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlOutputBuffer>() as u64,
    );
    let fresh69 = &mut ((*outbuf).buffer);
    *fresh69 = buf;
    let fresh70 = &mut ((*outbuf).encoder);
    *fresh70 = 0 as xmlCharEncodingHandlerPtr;
    let fresh71 = &mut ((*outbuf).writecallback);
    *fresh71 = None;
    let fresh72 = &mut ((*outbuf).closecallback);
    *fresh72 = None;
    let fresh73 = &mut ((*outbuf).context);
    *fresh73 = 0 as *mut libc::c_void;
    (*outbuf).written = 0 as i32;
    use_0 = xmlBufUse(buf);
    oldalloc = xmlBufGetAllocationScheme(buf);
    xmlBufSetAllocationScheme(buf, XML_BUFFER_ALLOC_DOUBLEIT);
    xmlNodeDumpOutput(outbuf, doc, cur, level, format, 0 as *const i8);
    xmlBufSetAllocationScheme(buf, oldalloc as xmlBufferAllocationScheme);
    xmlFree.expect("non-null function pointer")(outbuf as *mut libc::c_void);
    ret = (xmlBufUse(buf)).wrapping_sub(use_0) as i32;
    return ret as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn xmlElemDump(
    mut f: * mut crate::src::tree::_IO_FILE,
    mut doc: * mut crate::src::threads::_xmlDoc,
    mut cur: * mut crate::src::threads::_xmlNode,
) {
    let mut outbuf: * mut crate::src::threads::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    xmlInitParser();
    if cur.is_null() {
        return;
    }
    outbuf = xmlOutputBufferCreateFile(f, 0 as xmlCharEncodingHandlerPtr);
    if outbuf.is_null() {
        return;
    }
    if !doc.is_null()
        && (*doc).type_0 as u32
            == XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        htmlNodeDumpOutput(outbuf, doc, cur, 0 as *const i8);
    } else {
        xmlNodeDumpOutput(
            outbuf,
            doc,
            cur,
            0 as i32,
            1 as i32,
            0 as *const i8,
        );
    }
    xmlOutputBufferClose(outbuf);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeDumpOutput(
    mut buf: * mut crate::src::threads::_xmlOutputBuffer,
    mut doc: * mut crate::src::threads::_xmlDoc,
    mut cur: * mut crate::src::threads::_xmlNode,
    mut level: i32,
    mut format: i32,
    mut encoding: * const i8,
) {
    let mut ctxt: crate::src::xmlsave::_xmlSaveCtxt<'_> = xmlSaveCtxt {
        _private: (0 as * mut core::ffi::c_void),
        type_0: 0,
        fd: 0,
        filename: Option::<&'_ u8>::None,
        encoding: 0 as *const xmlChar,
        handler: 0 as *mut xmlCharEncodingHandler,
        buf: 0 as *mut xmlOutputBuffer,
        options: 0,
        level: 0,
        format: 0,
        indent: [0; 61],
        indent_nr: 0,
        indent_size: 0,
        escape: None,
        escapeAttr: None,
    };
    let mut dtd: * mut crate::src::threads::_xmlDtd = 0 as *mut xmlDtd;
    let mut is_xhtml: i32 = 0 as i32;
    xmlInitParser();
    if buf.is_null() || cur.is_null() {
        return;
    }
    if encoding.is_null() {
        encoding = b"UTF-8\0" as *const u8 as *const i8;
    }
    memset(
        &mut ctxt as *mut xmlSaveCtxt as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSaveCtxt>() as u64,
    );
    ctxt.buf = buf;
    ctxt.level = level;
    ctxt.format = if format != 0 { 1 as i32 } else { 0 as i32 };
    ctxt.encoding = encoding as *const xmlChar;
    xmlSaveCtxtInit(&mut ctxt);
    ctxt.options |= XML_SAVE_AS_XML as i32;
    dtd = xmlGetIntSubset(doc as *const xmlDoc);
    if !dtd.is_null() {
        is_xhtml = xmlIsXHTML((*dtd).SystemID, (*dtd).ExternalID);
        if is_xhtml < 0 as i32 {
            is_xhtml = 0 as i32;
        }
    }
    if is_xhtml != 0 {
        xhtmlNodeDumpOutput(&mut ctxt, cur);
    } else {
        xmlNodeDumpOutputInternal(&mut ctxt, cur);
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlDocDumpFormatMemoryEnc<'a1>(
    mut out_doc: * mut crate::src::threads::_xmlDoc,
    mut doc_txt_ptr: Option<&'a1 mut * mut u8>,
    mut doc_txt_len: * mut i32,
    mut txt_encoding: * const i8,
    mut format: i32,
) {
    let mut ctxt: crate::src::xmlsave::_xmlSaveCtxt<'_> = xmlSaveCtxt {
        _private: (0 as * mut core::ffi::c_void),
        type_0: 0,
        fd: 0,
        filename: Option::<&'_ u8>::None,
        encoding: 0 as *const xmlChar,
        handler: 0 as *mut xmlCharEncodingHandler,
        buf: 0 as *mut xmlOutputBuffer,
        options: 0,
        level: 0,
        format: 0,
        indent: [0; 61],
        indent_nr: 0,
        indent_size: 0,
        escape: None,
        escapeAttr: None,
    };
    let mut dummy: i32 = 0 as i32;
    let mut out_buff: * mut crate::src::threads::_xmlOutputBuffer = 0 as xmlOutputBufferPtr;
    let mut conv_hdlr: * mut crate::src::threads::_xmlCharEncodingHandler = 0 as xmlCharEncodingHandlerPtr;
    if doc_txt_len.is_null() {
        doc_txt_len = &mut dummy;
    }
    if borrow(& doc_txt_ptr).is_none() {
        *doc_txt_len = 0 as i32;
        return;
    }
    *(borrow_mut(&mut doc_txt_ptr)).unwrap() = 0 as *mut xmlChar;
    *doc_txt_len = 0 as i32;
    if out_doc.is_null() {
        return;
    }
    if txt_encoding.is_null() {
        txt_encoding = (*out_doc).encoding as *const i8;
    }
    if !txt_encoding.is_null() {
        conv_hdlr = xmlFindCharEncodingHandler(txt_encoding);
        if conv_hdlr.is_null() {
            xmlSaveErr(
                XML_SAVE_UNKNOWN_ENCODING as i32,
                out_doc as xmlNodePtr,
                txt_encoding,
            );
            return;
        }
    }
    out_buff = xmlAllocOutputBuffer(conv_hdlr);
    if out_buff.is_null() {
        xmlSaveErrMemory(b"creating buffer\0" as *const u8 as *const i8);
        return;
    }
    memset(
        &mut ctxt as *mut xmlSaveCtxt as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSaveCtxt>() as u64,
    );
    ctxt.buf = out_buff;
    ctxt.level = 0 as i32;
    ctxt.format = if format != 0 { 1 as i32 } else { 0 as i32 };
    ctxt.encoding = txt_encoding as *const xmlChar;
    xmlSaveCtxtInit(&mut ctxt);
    ctxt.options |= XML_SAVE_AS_XML as i32;
    xmlDocContentDumpOutput(&mut ctxt, out_doc);
    xmlOutputBufferFlush(out_buff);
    if !((*out_buff).conv).is_null() {
        *doc_txt_len = xmlBufUse((*out_buff).conv) as i32;
        *(borrow_mut(&mut doc_txt_ptr)).unwrap() = xmlStrndup(
            xmlBufContent((*out_buff).conv as *const xmlBuf),
            *doc_txt_len,
        );
    } else {
        *doc_txt_len = xmlBufUse((*out_buff).buffer) as i32;
        *(borrow_mut(&mut doc_txt_ptr)).unwrap() = xmlStrndup(
            xmlBufContent((*out_buff).buffer as *const xmlBuf),
            *doc_txt_len,
        );
    }
    xmlOutputBufferClose(out_buff);
    if (*(borrow(& doc_txt_ptr)).unwrap()).is_null() && *doc_txt_len > 0 as i32 {
        *doc_txt_len = 0 as i32;
        xmlSaveErrMemory(b"creating output\0" as *const u8 as *const i8);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlDocDumpMemory<'a1>(
    mut cur: * mut crate::src::threads::_xmlDoc,
    mut mem: Option<&'a1 mut * mut u8>,
    mut size: * mut i32,
) {
    xmlDocDumpFormatMemoryEnc(
        cur,
        borrow_mut(&mut mem),
        size,
        0 as *const i8,
        0 as i32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlDocDumpFormatMemory<'a1>(
    mut cur: * mut crate::src::threads::_xmlDoc,
    mut mem: Option<&'a1 mut * mut u8>,
    mut size: * mut i32,
    mut format: i32,
) {
    xmlDocDumpFormatMemoryEnc(cur, borrow_mut(&mut mem), size, 0 as *const i8, format);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDocDumpMemoryEnc<'a1>(
    mut out_doc: * mut crate::src::threads::_xmlDoc,
    mut doc_txt_ptr: Option<&'a1 mut * mut u8>,
    mut doc_txt_len: * mut i32,
    mut txt_encoding: * const i8,
) {
    xmlDocDumpFormatMemoryEnc(
        out_doc,
        borrow_mut(&mut doc_txt_ptr),
        doc_txt_len,
        txt_encoding,
        0 as i32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlDocFormatDump(
    mut f: * mut crate::src::tree::_IO_FILE,
    mut cur: * mut crate::src::threads::_xmlDoc,
    mut format: i32,
) -> i32 {
    let mut ctxt: crate::src::xmlsave::_xmlSaveCtxt<'_> = xmlSaveCtxt {
        _private: (0 as * mut core::ffi::c_void),
        type_0: 0,
        fd: 0,
        filename: Option::<&'_ u8>::None,
        encoding: 0 as *const xmlChar,
        handler: 0 as *mut xmlCharEncodingHandler,
        buf: 0 as *mut xmlOutputBuffer,
        options: 0,
        level: 0,
        format: 0,
        indent: [0; 61],
        indent_nr: 0,
        indent_size: 0,
        escape: None,
        escapeAttr: None,
    };
    let mut buf: * mut crate::src::threads::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    let mut encoding: * const i8 = 0 as *const i8;
    let mut handler: * mut crate::src::threads::_xmlCharEncodingHandler = 0 as xmlCharEncodingHandlerPtr;
    let mut ret: i32 = 0;
    if cur.is_null() {
        return -(1 as i32);
    }
    encoding = (*cur).encoding as *const i8;
    if !encoding.is_null() {
        handler = xmlFindCharEncodingHandler(encoding);
        if handler.is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*cur).encoding as *mut i8 as *mut libc::c_void);
            let fresh74 = &mut ((*cur).encoding);
            *fresh74 = 0 as *const xmlChar;
            encoding = 0 as *const i8;
        }
    }
    buf = xmlOutputBufferCreateFile(f, handler);
    if buf.is_null() {
        return -(1 as i32);
    }
    memset(
        &mut ctxt as *mut xmlSaveCtxt as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSaveCtxt>() as u64,
    );
    ctxt.buf = buf;
    ctxt.level = 0 as i32;
    ctxt.format = if format != 0 { 1 as i32 } else { 0 as i32 };
    ctxt.encoding = encoding as *const xmlChar;
    xmlSaveCtxtInit(&mut ctxt);
    ctxt.options |= XML_SAVE_AS_XML as i32;
    xmlDocContentDumpOutput(&mut ctxt, cur);
    ret = xmlOutputBufferClose(buf);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDocDump(
    mut f: * mut crate::src::tree::_IO_FILE,
    mut cur: * mut crate::src::threads::_xmlDoc,
) -> i32 {
    return xmlDocFormatDump(f, cur, 0 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveFileTo(
    mut buf: * mut crate::src::threads::_xmlOutputBuffer,
    mut cur: * mut crate::src::threads::_xmlDoc,
    mut encoding: * const i8,
) -> i32 {
    let mut ctxt: crate::src::xmlsave::_xmlSaveCtxt<'_> = xmlSaveCtxt {
        _private: (0 as * mut core::ffi::c_void),
        type_0: 0,
        fd: 0,
        filename: Option::<&'_ u8>::None,
        encoding: 0 as *const xmlChar,
        handler: 0 as *mut xmlCharEncodingHandler,
        buf: 0 as *mut xmlOutputBuffer,
        options: 0,
        level: 0,
        format: 0,
        indent: [0; 61],
        indent_nr: 0,
        indent_size: 0,
        escape: None,
        escapeAttr: None,
    };
    let mut ret: i32 = 0;
    if buf.is_null() {
        return -(1 as i32);
    }
    if cur.is_null() {
        xmlOutputBufferClose(buf);
        return -(1 as i32);
    }
    memset(
        &mut ctxt as *mut xmlSaveCtxt as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSaveCtxt>() as u64,
    );
    ctxt.buf = buf;
    ctxt.level = 0 as i32;
    ctxt.format = 0 as i32;
    ctxt.encoding = encoding as *const xmlChar;
    xmlSaveCtxtInit(&mut ctxt);
    ctxt.options |= XML_SAVE_AS_XML as i32;
    xmlDocContentDumpOutput(&mut ctxt, cur);
    ret = xmlOutputBufferClose(buf);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveFormatFileTo(
    mut buf: * mut crate::src::threads::_xmlOutputBuffer,
    mut cur: * mut crate::src::threads::_xmlDoc,
    mut encoding: * const i8,
    mut format: i32,
) -> i32 {
    let mut ctxt: crate::src::xmlsave::_xmlSaveCtxt<'_> = xmlSaveCtxt {
        _private: (0 as * mut core::ffi::c_void),
        type_0: 0,
        fd: 0,
        filename: Option::<&'_ u8>::None,
        encoding: 0 as *const xmlChar,
        handler: 0 as *mut xmlCharEncodingHandler,
        buf: 0 as *mut xmlOutputBuffer,
        options: 0,
        level: 0,
        format: 0,
        indent: [0; 61],
        indent_nr: 0,
        indent_size: 0,
        escape: None,
        escapeAttr: None,
    };
    let mut ret: i32 = 0;
    if buf.is_null() {
        return -(1 as i32);
    }
    if cur.is_null()
        || (*cur).type_0 as u32
            != XML_DOCUMENT_NODE as i32 as u32
            && (*cur).type_0 as u32
                != XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        xmlOutputBufferClose(buf);
        return -(1 as i32);
    }
    memset(
        &mut ctxt as *mut xmlSaveCtxt as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSaveCtxt>() as u64,
    );
    ctxt.buf = buf;
    ctxt.level = 0 as i32;
    ctxt.format = if format != 0 { 1 as i32 } else { 0 as i32 };
    ctxt.encoding = encoding as *const xmlChar;
    xmlSaveCtxtInit(&mut ctxt);
    ctxt.options |= XML_SAVE_AS_XML as i32;
    xmlDocContentDumpOutput(&mut ctxt, cur);
    ret = xmlOutputBufferClose(buf);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveFormatFileEnc(
    mut filename: * const i8,
    mut cur: * mut crate::src::threads::_xmlDoc,
    mut encoding: * const i8,
    mut format: i32,
) -> i32 {
    let mut ctxt: crate::src::xmlsave::_xmlSaveCtxt<'_> = xmlSaveCtxt {
        _private: (0 as * mut core::ffi::c_void),
        type_0: 0,
        fd: 0,
        filename: Option::<&'_ u8>::None,
        encoding: 0 as *const xmlChar,
        handler: 0 as *mut xmlCharEncodingHandler,
        buf: 0 as *mut xmlOutputBuffer,
        options: 0,
        level: 0,
        format: 0,
        indent: [0; 61],
        indent_nr: 0,
        indent_size: 0,
        escape: None,
        escapeAttr: None,
    };
    let mut buf: * mut crate::src::threads::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    let mut handler: * mut crate::src::threads::_xmlCharEncodingHandler = 0 as xmlCharEncodingHandlerPtr;
    let mut ret: i32 = 0;
    if cur.is_null() {
        return -(1 as i32);
    }
    if encoding.is_null() {
        encoding = (*cur).encoding as *const i8;
    }
    if !encoding.is_null() {
        handler = xmlFindCharEncodingHandler(encoding);
        if handler.is_null() {
            return -(1 as i32);
        }
    }
    if (*cur).compression < 0 as i32 {
        (*cur).compression = xmlGetCompressMode();
    }
    buf = xmlOutputBufferCreateFilename(filename, handler, (*cur).compression);
    if buf.is_null() {
        return -(1 as i32);
    }
    memset(
        &mut ctxt as *mut xmlSaveCtxt as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSaveCtxt>() as u64,
    );
    ctxt.buf = buf;
    ctxt.level = 0 as i32;
    ctxt.format = if format != 0 { 1 as i32 } else { 0 as i32 };
    ctxt.encoding = encoding as *const xmlChar;
    xmlSaveCtxtInit(&mut ctxt);
    ctxt.options |= XML_SAVE_AS_XML as i32;
    xmlDocContentDumpOutput(&mut ctxt, cur);
    ret = xmlOutputBufferClose(buf);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveFileEnc(
    mut filename: * const i8,
    mut cur: * mut crate::src::threads::_xmlDoc,
    mut encoding: * const i8,
) -> i32 {
    return xmlSaveFormatFileEnc(filename, cur, encoding, 0 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveFormatFile(
    mut filename: * const i8,
    mut cur: * mut crate::src::threads::_xmlDoc,
    mut format: i32,
) -> i32 {
    return xmlSaveFormatFileEnc(filename, cur, 0 as *const i8, format);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSaveFile(
    mut filename: * const i8,
    mut cur: * mut crate::src::threads::_xmlDoc,
) -> i32 {
    return xmlSaveFormatFileEnc(
        filename,
        cur,
        0 as *const i8,
        0 as i32,
    );
}
use crate::laertes_rt::*;
