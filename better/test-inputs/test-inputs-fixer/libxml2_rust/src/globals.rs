use :: libc;
extern "C" {
    pub type _xmlBuf;
    pub type _xmlDict;
    pub type _xmlMutex;
    fn __xmlGlobalInitMutexDestroy();
    fn xmlCharStrdup(cur: *const i8) -> *mut xmlChar;
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    static mut __xmlRegisterCallbacks: i32;
    fn malloc(_: u64) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn xmlParserError(ctx: *mut libc::c_void, msg: *const i8, _: ...);
    fn xmlParserWarning(ctx: *mut libc::c_void, msg: *const i8, _: ...);
    fn xmlResetError(err: xmlErrorPtr);
    fn __xmlParserInputBufferCreateFilename(
        URI: *const i8,
        enc: xmlCharEncoding,
    ) -> xmlParserInputBufferPtr;
    fn __xmlOutputBufferCreateFilename(
        URI: *const i8,
        encoder: xmlCharEncodingHandlerPtr,
        compression: i32,
    ) -> xmlOutputBufferPtr;
    fn xmlSAX2GetPublicId(ctx: *mut libc::c_void) -> *const xmlChar;
    fn xmlSAX2GetSystemId(ctx: *mut libc::c_void) -> *const xmlChar;
    fn xmlSAX2SetDocumentLocator(ctx: *mut libc::c_void, loc: xmlSAXLocatorPtr);
    fn xmlSAX2GetLineNumber(ctx: *mut libc::c_void) -> i32;
    fn xmlSAX2GetColumnNumber(ctx: *mut libc::c_void) -> i32;
    fn xmlSAX2IsStandalone(ctx: *mut libc::c_void) -> i32;
    fn xmlSAX2HasInternalSubset(ctx: *mut libc::c_void) -> i32;
    fn xmlSAX2HasExternalSubset(ctx: *mut libc::c_void) -> i32;
    fn xmlSAX2InternalSubset(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    );
    fn xmlSAX2ExternalSubset(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    );
    fn xmlSAX2GetEntity(ctx: *mut libc::c_void, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlSAX2GetParameterEntity(ctx: *mut libc::c_void, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlSAX2ResolveEntity(
        ctx: *mut libc::c_void,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
    ) -> xmlParserInputPtr;
    fn xmlSAX2EntityDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: i32,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
        content: *mut xmlChar,
    );
    fn xmlSAX2AttributeDecl(
        ctx: *mut libc::c_void,
        elem: *const xmlChar,
        fullname: *const xmlChar,
        type_0: i32,
        def: i32,
        defaultValue: *const xmlChar,
        tree: xmlEnumerationPtr,
    );
    fn xmlSAX2ElementDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: i32,
        content: xmlElementContentPtr,
    );
    fn xmlSAX2NotationDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
    );
    fn xmlSAX2UnparsedEntityDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
        notationName: *const xmlChar,
    );
    fn xmlSAX2StartDocument(ctx: *mut libc::c_void);
    fn xmlSAX2EndDocument(ctx: *mut libc::c_void);
    fn xmlSAX2StartElement(
        ctx: *mut libc::c_void,
        fullname: *const xmlChar,
        atts: *mut *const xmlChar,
    );
    fn xmlSAX2EndElement(ctx: *mut libc::c_void, name: *const xmlChar);
    fn xmlSAX2Reference(ctx: *mut libc::c_void, name: *const xmlChar);
    fn xmlSAX2Characters(ctx: *mut libc::c_void, ch: *const xmlChar, len: i32);
    fn xmlSAX2IgnorableWhitespace(ctx: *mut libc::c_void, ch: *const xmlChar, len: i32);
    fn xmlSAX2ProcessingInstruction(
        ctx: *mut libc::c_void,
        target: *const xmlChar,
        data: *const xmlChar,
    );
    fn xmlSAX2Comment(ctx: *mut libc::c_void, value: *const xmlChar);
    fn xmlSAX2CDataBlock(ctx: *mut libc::c_void, value: *const xmlChar, len: i32);
    fn xmlNewMutex() -> xmlMutexPtr;
    fn xmlFreeMutex(tok: xmlMutexPtr);
    fn xmlMutexLock(tok: xmlMutexPtr);
    fn xmlMutexUnlock(tok: xmlMutexPtr);
    fn xmlIsMainThread() -> i32;
    fn xmlGetGlobalState() -> xmlGlobalStatePtr;
    fn initxmlDefaultSAXHandler(hdlr: *mut xmlSAXHandlerV1, warning: i32);
    fn inithtmlDefaultSAXHandler(hdlr: *mut xmlSAXHandlerV1);
    fn xmlGenericErrorDefaultFunc(ctx: *mut libc::c_void, msg: *const i8, _: ...);
}
pub type xmlChar = u8;
pub type size_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInputBuffer {
    pub context: *mut libc::c_void,
    pub readcallback: xmlInputReadCallback,
    pub closecallback: xmlInputCloseCallback,
    pub encoder: xmlCharEncodingHandlerPtr,
    pub buffer: xmlBufPtr,
    pub raw: xmlBufPtr,
    pub compressed: i32,
    pub error: i32,
    pub rawconsumed: u64,
}
pub type xmlBufPtr = *mut xmlBuf;
pub type xmlBuf = _xmlBuf;
pub type xmlCharEncodingHandlerPtr = *mut xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = _xmlCharEncodingHandler;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlCharEncodingHandler {
    pub name: *mut i8,
    pub input: xmlCharEncodingInputFunc,
    pub output: xmlCharEncodingOutputFunc,
    pub iconv_in: iconv_t,
    pub iconv_out: iconv_t,
}
pub type iconv_t = *mut libc::c_void;
pub type xmlCharEncodingOutputFunc =
    Option<unsafe extern "C" fn(*mut u8, *mut i32, *const u8, *mut i32) -> i32>;
pub type xmlCharEncodingInputFunc =
    Option<unsafe extern "C" fn(*mut u8, *mut i32, *const u8, *mut i32) -> i32>;
pub type xmlInputCloseCallback = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type xmlInputReadCallback =
    Option<unsafe extern "C" fn(*mut libc::c_void, *mut i8, i32) -> i32>;
pub type xmlParserInputBuffer = _xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = *mut xmlParserInputBuffer;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlOutputBuffer {
    pub context: *mut libc::c_void,
    pub writecallback: xmlOutputWriteCallback,
    pub closecallback: xmlOutputCloseCallback,
    pub encoder: xmlCharEncodingHandlerPtr,
    pub buffer: xmlBufPtr,
    pub conv: xmlBufPtr,
    pub written: i32,
    pub error: i32,
}
pub type xmlOutputCloseCallback = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type xmlOutputWriteCallback =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, i32) -> i32>;
pub type xmlOutputBuffer = _xmlOutputBuffer;
pub type xmlOutputBufferPtr = *mut xmlOutputBuffer;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInput {
    pub buf: xmlParserInputBufferPtr,
    pub filename: *const i8,
    pub directory: *const i8,
    pub base: *const xmlChar,
    pub cur: *const xmlChar,
    pub end: *const xmlChar,
    pub length: i32,
    pub line: i32,
    pub col: i32,
    pub consumed: u64,
    pub free: xmlParserInputDeallocate,
    pub encoding: *const xmlChar,
    pub version: *const xmlChar,
    pub standalone: i32,
    pub id: i32,
}
pub type xmlParserInputDeallocate = Option<unsafe extern "C" fn(*mut xmlChar) -> ()>;
pub type xmlParserInput = _xmlParserInput;
pub type xmlParserInputPtr = *mut xmlParserInput;
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
pub type xmlNodePtr = *mut xmlNode;
pub type xmlNode = _xmlNode;
pub type xmlStructuredErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> ()>;
pub type xmlErrorPtr = *mut xmlError;
pub type externalSubsetSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
pub type cdataBlockSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> ()>;
pub type getParameterEntitySAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr>;
pub type xmlEntityPtr = *mut xmlEntity;
pub type xmlEntity = _xmlEntity;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlEntity {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlDtd,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub orig: *mut xmlChar,
    pub content: *mut xmlChar,
    pub length: i32,
    pub etype: xmlEntityType,
    pub ExternalID: *const xmlChar,
    pub SystemID: *const xmlChar,
    pub nexte: *mut _xmlEntity,
    pub URI: *const xmlChar,
    pub owner: i32,
    pub checked: i32,
}
pub type xmlEntityType = u32;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type errorSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type warningSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type commentSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type processingInstructionSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> ()>;
pub type ignorableWhitespaceSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> ()>;
pub type charactersSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> ()>;
pub type referenceSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type endElementSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type startElementSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *mut *const xmlChar) -> ()>;
pub type endDocumentSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type startDocumentSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type setDocumentLocatorSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> ()>;
pub type xmlSAXLocatorPtr = *mut xmlSAXLocator;
pub type xmlSAXLocator = _xmlSAXLocator;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXLocator {
    pub getPublicId: Option<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getSystemId: Option<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getLineNumber: Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>,
    pub getColumnNumber: Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>,
}
pub type unparsedEntityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type elementDeclSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32, xmlElementContentPtr) -> (),
>;
pub type xmlElementContentPtr = *mut xmlElementContent;
pub type xmlElementContent = _xmlElementContent;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlElementContent {
    pub type_0: xmlElementContentType,
    pub ocur: xmlElementContentOccur,
    pub name: *const xmlChar,
    pub c1: *mut _xmlElementContent,
    pub c2: *mut _xmlElementContent,
    pub parent: *mut _xmlElementContent,
    pub prefix: *const xmlChar,
}
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
pub type attributeDeclSAXFunc = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        i32,
        i32,
        *const xmlChar,
        xmlEnumerationPtr,
    ) -> (),
>;
pub type xmlEnumerationPtr = *mut xmlEnumeration;
pub type xmlEnumeration = _xmlEnumeration;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlEnumeration {
    pub next: *mut _xmlEnumeration,
    pub name: *const xmlChar,
}
pub type notationDeclSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
pub type entityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        i32,
        *const xmlChar,
        *const xmlChar,
        *mut xmlChar,
    ) -> (),
>;
pub type getEntitySAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr>;
pub type resolveEntitySAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> xmlParserInputPtr,
>;
pub type hasExternalSubsetSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type hasInternalSubsetSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type isStandaloneSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type internalSubsetSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
pub type xmlBufferAllocationScheme = u32;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
pub type xmlGenericErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXHandlerV1 {
    pub internalSubset: internalSubsetSAXFunc,
    pub isStandalone: isStandaloneSAXFunc,
    pub hasInternalSubset: hasInternalSubsetSAXFunc,
    pub hasExternalSubset: hasExternalSubsetSAXFunc,
    pub resolveEntity: resolveEntitySAXFunc,
    pub getEntity: getEntitySAXFunc,
    pub entityDecl: entityDeclSAXFunc,
    pub notationDecl: notationDeclSAXFunc,
    pub attributeDecl: attributeDeclSAXFunc,
    pub elementDecl: elementDeclSAXFunc,
    pub unparsedEntityDecl: unparsedEntityDeclSAXFunc,
    pub setDocumentLocator: setDocumentLocatorSAXFunc,
    pub startDocument: startDocumentSAXFunc,
    pub endDocument: endDocumentSAXFunc,
    pub startElement: startElementSAXFunc,
    pub endElement: endElementSAXFunc,
    pub reference: referenceSAXFunc,
    pub characters: charactersSAXFunc,
    pub ignorableWhitespace: ignorableWhitespaceSAXFunc,
    pub processingInstruction: processingInstructionSAXFunc,
    pub comment: commentSAXFunc,
    pub warning: warningSAXFunc,
    pub error: errorSAXFunc,
    pub fatalError: fatalErrorSAXFunc,
    pub getParameterEntity: getParameterEntitySAXFunc,
    pub cdataBlock: cdataBlockSAXFunc,
    pub externalSubset: externalSubsetSAXFunc,
    pub initialized: u32,
}
pub type xmlSAXHandlerV1 = _xmlSAXHandlerV1;
pub type xmlCharEncoding = i32;
pub const XML_CHAR_ENCODING_ASCII: xmlCharEncoding = 22;
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
pub type xmlFreeFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type xmlReallocFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void>;
pub type xmlStrdupFunc = Option<unsafe extern "C" fn(*const i8) -> *mut i8>;
pub type xmlMutexPtr = *mut xmlMutex;
pub type xmlMutex = _xmlMutex;
pub type xmlParserInputBufferCreateFilenameFunc =
    Option<unsafe extern "C" fn(*const i8, xmlCharEncoding) -> xmlParserInputBufferPtr>;
pub type xmlOutputBufferCreateFilenameFunc =
    Option<unsafe extern "C" fn(*const i8, xmlCharEncodingHandlerPtr, i32) -> xmlOutputBufferPtr>;
pub type xmlRegisterNodeFunc = Option<unsafe extern "C" fn(xmlNodePtr) -> ()>;
pub type xmlDeregisterNodeFunc = Option<unsafe extern "C" fn(xmlNodePtr) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlGlobalState {
    pub xmlParserVersion: *const i8,
    pub xmlDefaultSAXLocator: xmlSAXLocator,
    pub xmlDefaultSAXHandler: xmlSAXHandlerV1,
    pub docbDefaultSAXHandler: xmlSAXHandlerV1,
    pub htmlDefaultSAXHandler: xmlSAXHandlerV1,
    pub xmlFree: xmlFreeFunc,
    pub xmlMalloc: xmlMallocFunc,
    pub xmlMemStrdup: xmlStrdupFunc,
    pub xmlRealloc: xmlReallocFunc,
    pub xmlGenericError: xmlGenericErrorFunc,
    pub xmlStructuredError: xmlStructuredErrorFunc,
    pub xmlGenericErrorContext: *mut libc::c_void,
    pub oldXMLWDcompatibility: i32,
    pub xmlBufferAllocScheme: xmlBufferAllocationScheme,
    pub xmlDefaultBufferSize: i32,
    pub xmlSubstituteEntitiesDefaultValue: i32,
    pub xmlDoValidityCheckingDefaultValue: i32,
    pub xmlGetWarningsDefaultValue: i32,
    pub xmlKeepBlanksDefaultValue: i32,
    pub xmlLineNumbersDefaultValue: i32,
    pub xmlLoadExtDtdDefaultValue: i32,
    pub xmlParserDebugEntities: i32,
    pub xmlPedanticParserDefaultValue: i32,
    pub xmlSaveNoEmptyTags: i32,
    pub xmlIndentTreeOutput: i32,
    pub xmlTreeIndentString: *const i8,
    pub xmlRegisterNodeDefaultValue: xmlRegisterNodeFunc,
    pub xmlDeregisterNodeDefaultValue: xmlDeregisterNodeFunc,
    pub xmlMallocAtomic: xmlMallocFunc,
    pub xmlLastError: xmlError,
    pub xmlParserInputBufferCreateFilenameValue: xmlParserInputBufferCreateFilenameFunc,
    pub xmlOutputBufferCreateFilenameValue: xmlOutputBufferCreateFilenameFunc,
    pub xmlStructuredErrorContext: *mut libc::c_void,
}
pub type xmlGlobalState = _xmlGlobalState;
pub type xmlGlobalStatePtr = *mut xmlGlobalState;
static mut xmlThrDefMutex: xmlMutexPtr = 0 as *const xmlMutex as xmlMutexPtr;
#[no_mangle]
pub extern "C" fn xmlInitGlobals() {
    if (unsafe { xmlThrDefMutex }).is_null() {
        (unsafe { xmlThrDefMutex = xmlNewMutex() });
    }
}
#[no_mangle]
pub static mut xmlFree: xmlFreeFunc =
     Some(free as unsafe extern "C" fn(*mut libc::c_void) -> ());
#[no_mangle]
pub static mut xmlMalloc: xmlMallocFunc =
     Some(malloc as unsafe extern "C" fn(u64) -> *mut libc::c_void);
#[no_mangle]
pub static mut xmlMallocAtomic: xmlMallocFunc =
     Some(malloc as unsafe extern "C" fn(u64) -> *mut libc::c_void);
#[no_mangle]
pub static mut xmlRealloc: xmlReallocFunc =
     Some(realloc as unsafe extern "C" fn(*mut libc::c_void, u64) -> *mut libc::c_void);
extern "C" fn xmlPosixStrdup(mut cur: *const i8) -> *mut i8 {
    return (unsafe { xmlCharStrdup(cur) }) as *mut i8;
}
#[no_mangle]
pub static mut xmlMemStrdup: xmlStrdupFunc =
     Some(xmlPosixStrdup as unsafe extern "C" fn(*const i8) -> *mut i8);
#[no_mangle]
pub static mut xmlParserVersion: *const i8 = b"21000-GITv2.10.0\0" as *const u8 as *const i8;
#[no_mangle]
pub static mut xmlBufferAllocScheme: xmlBufferAllocationScheme = XML_BUFFER_ALLOC_EXACT;
static mut xmlBufferAllocSchemeThrDef: xmlBufferAllocationScheme = XML_BUFFER_ALLOC_EXACT;
#[no_mangle]
pub static mut xmlDefaultBufferSize: i32 = 4096 as i32;
static mut xmlDefaultBufferSizeThrDef: i32 = 4096 as i32;
#[no_mangle]
pub static mut oldXMLWDcompatibility: i32 = 0 as i32;
#[no_mangle]
pub static mut xmlParserDebugEntities: i32 = 0 as i32;
static mut xmlParserDebugEntitiesThrDef: i32 = 0 as i32;
#[no_mangle]
pub static mut xmlDoValidityCheckingDefaultValue: i32 = 0 as i32;
static mut xmlDoValidityCheckingDefaultValueThrDef: i32 = 0 as i32;
#[no_mangle]
pub static mut xmlGetWarningsDefaultValue: i32 = 1 as i32;
static mut xmlGetWarningsDefaultValueThrDef: i32 = 1 as i32;
#[no_mangle]
pub static mut xmlLoadExtDtdDefaultValue: i32 = 0 as i32;
static mut xmlLoadExtDtdDefaultValueThrDef: i32 = 0 as i32;
#[no_mangle]
pub static mut xmlPedanticParserDefaultValue: i32 = 0 as i32;
static mut xmlPedanticParserDefaultValueThrDef: i32 = 0 as i32;
#[no_mangle]
pub static mut xmlLineNumbersDefaultValue: i32 = 0 as i32;
static mut xmlLineNumbersDefaultValueThrDef: i32 = 0 as i32;
#[no_mangle]
pub static mut xmlKeepBlanksDefaultValue: i32 = 1 as i32;
static mut xmlKeepBlanksDefaultValueThrDef: i32 = 1 as i32;
#[no_mangle]
pub static mut xmlSubstituteEntitiesDefaultValue: i32 = 0 as i32;
static mut xmlSubstituteEntitiesDefaultValueThrDef: i32 = 0 as i32;
#[no_mangle]
pub static mut xmlRegisterNodeDefaultValue: xmlRegisterNodeFunc = None;
static mut xmlRegisterNodeDefaultValueThrDef: xmlRegisterNodeFunc = None;
#[no_mangle]
pub static mut xmlDeregisterNodeDefaultValue: xmlDeregisterNodeFunc = None;
static mut xmlDeregisterNodeDefaultValueThrDef: xmlDeregisterNodeFunc = None;
#[no_mangle]
pub static mut xmlParserInputBufferCreateFilenameValue: xmlParserInputBufferCreateFilenameFunc =
    None;
static mut xmlParserInputBufferCreateFilenameValueThrDef: xmlParserInputBufferCreateFilenameFunc =
    None;
#[no_mangle]
pub static mut xmlOutputBufferCreateFilenameValue: xmlOutputBufferCreateFilenameFunc = None;
static mut xmlOutputBufferCreateFilenameValueThrDef: xmlOutputBufferCreateFilenameFunc = None;
#[no_mangle]
pub static mut xmlGenericError: xmlGenericErrorFunc =  {
    Some(
        xmlGenericErrorDefaultFunc as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
    )
};
static mut xmlGenericErrorThrDef: xmlGenericErrorFunc =  {
    Some(
        xmlGenericErrorDefaultFunc as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
    )
};
#[no_mangle]
pub static mut xmlStructuredError: xmlStructuredErrorFunc = None;
static mut xmlStructuredErrorThrDef: xmlStructuredErrorFunc = None;
#[no_mangle]
pub static mut xmlGenericErrorContext: *mut libc::c_void =
    0 as *const libc::c_void as *mut libc::c_void;
static mut xmlGenericErrorContextThrDef: *mut libc::c_void =
    0 as *const libc::c_void as *mut libc::c_void;
#[no_mangle]
pub static mut xmlStructuredErrorContext: *mut libc::c_void =
    0 as *const libc::c_void as *mut libc::c_void;
static mut xmlStructuredErrorContextThrDef: *mut libc::c_void =
    0 as *const libc::c_void as *mut libc::c_void;
#[no_mangle]
pub static mut xmlLastError: xmlError = xmlError {
    domain: 0,
    code: 0,
    message: 0 as *const i8 as *mut i8,
    level: XML_ERR_NONE,
    file: 0 as *const i8 as *mut i8,
    line: 0,
    str1: 0 as *const i8 as *mut i8,
    str2: 0 as *const i8 as *mut i8,
    str3: 0 as *const i8 as *mut i8,
    int1: 0,
    int2: 0,
    ctxt: 0 as *const libc::c_void as *mut libc::c_void,
    node: 0 as *const libc::c_void as *mut libc::c_void,
};
#[no_mangle]
pub static mut xmlIndentTreeOutput: i32 = 1 as i32;
static mut xmlIndentTreeOutputThrDef: i32 = 1 as i32;
#[no_mangle]
pub static mut xmlTreeIndentString: *const i8 = b"  \0" as *const u8 as *const i8;
static mut xmlTreeIndentStringThrDef: *const i8 = b"  \0" as *const u8 as *const i8;
#[no_mangle]
pub static mut xmlSaveNoEmptyTags: i32 = 0 as i32;
static mut xmlSaveNoEmptyTagsThrDef: i32 = 0 as i32;
#[no_mangle]
pub static mut xmlDefaultSAXHandler: xmlSAXHandlerV1 =  {
    {
        let mut init = _xmlSAXHandlerV1 {
            internalSubset: Some(
                xmlSAX2InternalSubset
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            isStandalone: Some(
                xmlSAX2IsStandalone as unsafe extern "C" fn(*mut libc::c_void) -> i32,
            ),
            hasInternalSubset: Some(
                xmlSAX2HasInternalSubset as unsafe extern "C" fn(*mut libc::c_void) -> i32,
            ),
            hasExternalSubset: Some(
                xmlSAX2HasExternalSubset as unsafe extern "C" fn(*mut libc::c_void) -> i32,
            ),
            resolveEntity: Some(
                xmlSAX2ResolveEntity
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> xmlParserInputPtr,
            ),
            getEntity: Some(
                xmlSAX2GetEntity
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
            ),
            entityDecl: Some(
                xmlSAX2EntityDecl
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        i32,
                        *const xmlChar,
                        *const xmlChar,
                        *mut xmlChar,
                    ) -> (),
            ),
            notationDecl: Some(
                xmlSAX2NotationDecl
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            attributeDecl: Some(
                xmlSAX2AttributeDecl
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        i32,
                        i32,
                        *const xmlChar,
                        xmlEnumerationPtr,
                    ) -> (),
            ),
            elementDecl: Some(
                xmlSAX2ElementDecl
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        i32,
                        xmlElementContentPtr,
                    ) -> (),
            ),
            unparsedEntityDecl: Some(
                xmlSAX2UnparsedEntityDecl
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            setDocumentLocator: Some(
                xmlSAX2SetDocumentLocator
                    as unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
            ),
            startDocument: Some(
                xmlSAX2StartDocument as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            endDocument: Some(xmlSAX2EndDocument as unsafe extern "C" fn(*mut libc::c_void) -> ()),
            startElement: Some(
                xmlSAX2StartElement
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *mut *const xmlChar,
                    ) -> (),
            ),
            endElement: Some(
                xmlSAX2EndElement as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            reference: Some(
                xmlSAX2Reference as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            characters: Some(
                xmlSAX2Characters
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
            ),
            ignorableWhitespace: Some(
                xmlSAX2Characters
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
            ),
            processingInstruction: Some(
                xmlSAX2ProcessingInstruction
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            comment: Some(
                xmlSAX2Comment as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            warning: Some(
                xmlParserWarning as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            error: Some(
                xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            fatalError: Some(
                xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            getParameterEntity: Some(
                xmlSAX2GetParameterEntity
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
            ),
            cdataBlock: Some(
                xmlSAX2CDataBlock
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
            ),
            externalSubset: Some(
                xmlSAX2ExternalSubset
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            initialized: 0 as i32 as u32,
        };
        init
    }
};
#[no_mangle]
pub static mut xmlDefaultSAXLocator: xmlSAXLocator =  {
    {
        let mut init = _xmlSAXLocator {
            getPublicId: Some(
                xmlSAX2GetPublicId as unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar,
            ),
            getSystemId: Some(
                xmlSAX2GetSystemId as unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar,
            ),
            getLineNumber: Some(
                xmlSAX2GetLineNumber as unsafe extern "C" fn(*mut libc::c_void) -> i32,
            ),
            getColumnNumber: Some(
                xmlSAX2GetColumnNumber as unsafe extern "C" fn(*mut libc::c_void) -> i32,
            ),
        };
        init
    }
};
#[no_mangle]
pub static mut htmlDefaultSAXHandler: xmlSAXHandlerV1 =  {
    {
        let mut init = _xmlSAXHandlerV1 {
            internalSubset: Some(
                xmlSAX2InternalSubset
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            isStandalone: None,
            hasInternalSubset: None,
            hasExternalSubset: None,
            resolveEntity: None,
            getEntity: Some(
                xmlSAX2GetEntity
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
            ),
            entityDecl: None,
            notationDecl: None,
            attributeDecl: None,
            elementDecl: None,
            unparsedEntityDecl: None,
            setDocumentLocator: Some(
                xmlSAX2SetDocumentLocator
                    as unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
            ),
            startDocument: Some(
                xmlSAX2StartDocument as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            endDocument: Some(xmlSAX2EndDocument as unsafe extern "C" fn(*mut libc::c_void) -> ()),
            startElement: Some(
                xmlSAX2StartElement
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *mut *const xmlChar,
                    ) -> (),
            ),
            endElement: Some(
                xmlSAX2EndElement as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            reference: None,
            characters: Some(
                xmlSAX2Characters
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
            ),
            ignorableWhitespace: Some(
                xmlSAX2IgnorableWhitespace
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
            ),
            processingInstruction: Some(
                xmlSAX2ProcessingInstruction
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            comment: Some(
                xmlSAX2Comment as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            warning: Some(
                xmlParserWarning as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            error: Some(
                xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            fatalError: Some(
                xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            getParameterEntity: Some(
                xmlSAX2GetParameterEntity
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
            ),
            cdataBlock: Some(
                xmlSAX2CDataBlock
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
            ),
            externalSubset: None,
            initialized: 0 as i32 as u32,
        };
        init
    }
};
#[no_mangle]
pub extern "C" fn xmlInitializeGlobalState(mut gs: xmlGlobalStatePtr) {
    if (unsafe { xmlThrDefMutex }).is_null() {
        xmlInitGlobals();
    }
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    (unsafe { inithtmlDefaultSAXHandler(&mut (*gs).htmlDefaultSAXHandler) });
    (unsafe { (*gs).oldXMLWDcompatibility = 0 as i32 });
    (unsafe { (*gs).xmlBufferAllocScheme = xmlBufferAllocSchemeThrDef });
    (unsafe { (*gs).xmlDefaultBufferSize = xmlDefaultBufferSizeThrDef });
    (unsafe { initxmlDefaultSAXHandler(&mut (*gs).xmlDefaultSAXHandler, 1 as i32) });
    let fresh0 = unsafe { &mut ((*gs).xmlDefaultSAXLocator.getPublicId) };
    *fresh0 = Some(xmlSAX2GetPublicId as unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar);
    let fresh1 = unsafe { &mut ((*gs).xmlDefaultSAXLocator.getSystemId) };
    *fresh1 = Some(xmlSAX2GetSystemId as unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar);
    let fresh2 = unsafe { &mut ((*gs).xmlDefaultSAXLocator.getLineNumber) };
    *fresh2 = Some(xmlSAX2GetLineNumber as unsafe extern "C" fn(*mut libc::c_void) -> i32);
    let fresh3 = unsafe { &mut ((*gs).xmlDefaultSAXLocator.getColumnNumber) };
    *fresh3 = Some(xmlSAX2GetColumnNumber as unsafe extern "C" fn(*mut libc::c_void) -> i32);
    (unsafe { (*gs).xmlDoValidityCheckingDefaultValue = xmlDoValidityCheckingDefaultValueThrDef });
    let fresh4 = unsafe { &mut ((*gs).xmlFree) };
    *fresh4 = unsafe { ::std::mem::transmute::<
        Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
        xmlFreeFunc,
    >(Some(free as unsafe extern "C" fn(*mut libc::c_void) -> ())) };
    let fresh5 = unsafe { &mut ((*gs).xmlMalloc) };
    *fresh5 = unsafe { ::std::mem::transmute::<
        Option<unsafe extern "C" fn(u64) -> *mut libc::c_void>,
        xmlMallocFunc,
    >(Some(
        malloc as unsafe extern "C" fn(u64) -> *mut libc::c_void,
    )) };
    let fresh6 = unsafe { &mut ((*gs).xmlMallocAtomic) };
    *fresh6 = unsafe { ::std::mem::transmute::<
        Option<unsafe extern "C" fn(u64) -> *mut libc::c_void>,
        xmlMallocFunc,
    >(Some(
        malloc as unsafe extern "C" fn(u64) -> *mut libc::c_void,
    )) };
    let fresh7 = unsafe { &mut ((*gs).xmlRealloc) };
    *fresh7 = unsafe { ::std::mem::transmute::<
        Option<unsafe extern "C" fn(*mut libc::c_void, u64) -> *mut libc::c_void>,
        xmlReallocFunc,
    >(Some(
        realloc as unsafe extern "C" fn(*mut libc::c_void, u64) -> *mut libc::c_void,
    )) };
    let fresh8 = unsafe { &mut ((*gs).xmlMemStrdup) };
    *fresh8 = unsafe { ::std::mem::transmute::<
        Option<unsafe extern "C" fn(*const xmlChar) -> *mut xmlChar>,
        xmlStrdupFunc,
    >(Some(
        xmlStrdup as unsafe extern "C" fn(*const xmlChar) -> *mut xmlChar,
    )) };
    (unsafe { (*gs).xmlGetWarningsDefaultValue = xmlGetWarningsDefaultValueThrDef });
    (unsafe { (*gs).xmlIndentTreeOutput = xmlIndentTreeOutputThrDef });
    let fresh9 = unsafe { &mut ((*gs).xmlTreeIndentString) };
    *fresh9 = unsafe { xmlTreeIndentStringThrDef };
    (unsafe { (*gs).xmlKeepBlanksDefaultValue = xmlKeepBlanksDefaultValueThrDef });
    (unsafe { (*gs).xmlLineNumbersDefaultValue = xmlLineNumbersDefaultValueThrDef });
    (unsafe { (*gs).xmlLoadExtDtdDefaultValue = xmlLoadExtDtdDefaultValueThrDef });
    (unsafe { (*gs).xmlParserDebugEntities = xmlParserDebugEntitiesThrDef });
    let fresh10 = unsafe { &mut ((*gs).xmlParserVersion) };
    *fresh10 = b"21000\0" as *const u8 as *const i8;
    (unsafe { (*gs).xmlPedanticParserDefaultValue = xmlPedanticParserDefaultValueThrDef });
    (unsafe { (*gs).xmlSaveNoEmptyTags = xmlSaveNoEmptyTagsThrDef });
    (unsafe { (*gs).xmlSubstituteEntitiesDefaultValue = xmlSubstituteEntitiesDefaultValueThrDef });
    let fresh11 = unsafe { &mut ((*gs).xmlGenericError) };
    *fresh11 = unsafe { xmlGenericErrorThrDef };
    let fresh12 = unsafe { &mut ((*gs).xmlStructuredError) };
    *fresh12 = unsafe { xmlStructuredErrorThrDef };
    let fresh13 = unsafe { &mut ((*gs).xmlGenericErrorContext) };
    *fresh13 = unsafe { xmlGenericErrorContextThrDef };
    let fresh14 = unsafe { &mut ((*gs).xmlStructuredErrorContext) };
    *fresh14 = unsafe { xmlStructuredErrorContextThrDef };
    let fresh15 = unsafe { &mut ((*gs).xmlRegisterNodeDefaultValue) };
    *fresh15 = unsafe { xmlRegisterNodeDefaultValueThrDef };
    let fresh16 = unsafe { &mut ((*gs).xmlDeregisterNodeDefaultValue) };
    *fresh16 = unsafe { xmlDeregisterNodeDefaultValueThrDef };
    let fresh17 = unsafe { &mut ((*gs).xmlParserInputBufferCreateFilenameValue) };
    *fresh17 = unsafe { xmlParserInputBufferCreateFilenameValueThrDef };
    let fresh18 = unsafe { &mut ((*gs).xmlOutputBufferCreateFilenameValue) };
    *fresh18 = unsafe { xmlOutputBufferCreateFilenameValueThrDef };
    (unsafe { memset(
        &mut (*gs).xmlLastError as *mut xmlError as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlError>() as u64,
    ) });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
}
#[no_mangle]
pub extern "C" fn xmlCleanupGlobals() {
    (unsafe { xmlResetError(&mut xmlLastError) });
    if !(unsafe { xmlThrDefMutex }).is_null() {
        (unsafe { xmlFreeMutex(xmlThrDefMutex) });
        (unsafe { xmlThrDefMutex = 0 as xmlMutexPtr });
    }
    (unsafe { __xmlGlobalInitMutexDestroy() });
}
#[no_mangle]
pub extern "C" fn xmlThrDefSetGenericErrorFunc(
    mut ctx: *mut libc::c_void,
    mut handler: xmlGenericErrorFunc,
) {
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    (unsafe { xmlGenericErrorContextThrDef = ctx });
    if handler.is_some() {
        (unsafe { xmlGenericErrorThrDef = handler });
    } else {
        (unsafe { xmlGenericErrorThrDef = Some(
            xmlGenericErrorDefaultFunc
                as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
        ) });
    }
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
}
#[no_mangle]
pub extern "C" fn xmlThrDefSetStructuredErrorFunc(
    mut ctx: *mut libc::c_void,
    mut handler: xmlStructuredErrorFunc,
) {
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    (unsafe { xmlStructuredErrorContextThrDef = ctx });
    (unsafe { xmlStructuredErrorThrDef = handler });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
}
#[no_mangle]
pub extern "C" fn xmlRegisterNodeDefault(mut func: xmlRegisterNodeFunc) -> xmlRegisterNodeFunc {
    let mut old: xmlRegisterNodeFunc = unsafe { xmlRegisterNodeDefaultValue };
    (unsafe { __xmlRegisterCallbacks = 1 as i32 });
    (unsafe { xmlRegisterNodeDefaultValue = func });
    return old;
}
#[no_mangle]
pub extern "C" fn xmlThrDefRegisterNodeDefault(
    mut func: xmlRegisterNodeFunc,
) -> xmlRegisterNodeFunc {
    let mut old: xmlRegisterNodeFunc = None;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    old = unsafe { xmlRegisterNodeDefaultValueThrDef };
    (unsafe { __xmlRegisterCallbacks = 1 as i32 });
    (unsafe { xmlRegisterNodeDefaultValueThrDef = func });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return old;
}
#[no_mangle]
pub extern "C" fn xmlDeregisterNodeDefault(
    mut func: xmlDeregisterNodeFunc,
) -> xmlDeregisterNodeFunc {
    let mut old: xmlDeregisterNodeFunc = unsafe { xmlDeregisterNodeDefaultValue };
    (unsafe { __xmlRegisterCallbacks = 1 as i32 });
    (unsafe { xmlDeregisterNodeDefaultValue = func });
    return old;
}
#[no_mangle]
pub extern "C" fn xmlThrDefDeregisterNodeDefault(
    mut func: xmlDeregisterNodeFunc,
) -> xmlDeregisterNodeFunc {
    let mut old: xmlDeregisterNodeFunc = None;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    old = unsafe { xmlDeregisterNodeDefaultValueThrDef };
    (unsafe { __xmlRegisterCallbacks = 1 as i32 });
    (unsafe { xmlDeregisterNodeDefaultValueThrDef = func });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return old;
}
#[no_mangle]
pub extern "C" fn xmlThrDefParserInputBufferCreateFilenameDefault(
    mut func: xmlParserInputBufferCreateFilenameFunc,
) -> xmlParserInputBufferCreateFilenameFunc {
    let mut old: xmlParserInputBufferCreateFilenameFunc = None;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    old = unsafe { xmlParserInputBufferCreateFilenameValueThrDef };
    if old.is_none() {
        old = Some(
            __xmlParserInputBufferCreateFilename
                as unsafe extern "C" fn(*const i8, xmlCharEncoding) -> xmlParserInputBufferPtr,
        );
    }
    (unsafe { xmlParserInputBufferCreateFilenameValueThrDef = func });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return old;
}
#[no_mangle]
pub extern "C" fn xmlThrDefOutputBufferCreateFilenameDefault(
    mut func: xmlOutputBufferCreateFilenameFunc,
) -> xmlOutputBufferCreateFilenameFunc {
    let mut old: xmlOutputBufferCreateFilenameFunc = None;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    old = unsafe { xmlOutputBufferCreateFilenameValueThrDef };
    if old.is_none() {
        old = Some(
            __xmlOutputBufferCreateFilename
                as unsafe extern "C" fn(
                    *const i8,
                    xmlCharEncodingHandlerPtr,
                    i32,
                ) -> xmlOutputBufferPtr,
        );
    }
    (unsafe { xmlOutputBufferCreateFilenameValueThrDef = func });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return old;
}
#[no_mangle]
pub extern "C" fn __htmlDefaultSAXHandler() -> *mut xmlSAXHandlerV1 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut htmlDefaultSAXHandler };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .htmlDefaultSAXHandler };
    };
}
#[no_mangle]
pub extern "C" fn __xmlLastError() -> *mut xmlError {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlLastError };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlLastError };
    };
}
#[no_mangle]
pub extern "C" fn __oldXMLWDcompatibility() -> *mut i32 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut oldXMLWDcompatibility };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .oldXMLWDcompatibility };
    };
}
#[no_mangle]
pub extern "C" fn __xmlBufferAllocScheme() -> *mut xmlBufferAllocationScheme {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlBufferAllocScheme };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlBufferAllocScheme };
    };
}
#[no_mangle]
pub extern "C" fn xmlThrDefBufferAllocScheme(
    mut v: xmlBufferAllocationScheme,
) -> xmlBufferAllocationScheme {
    let mut ret: xmlBufferAllocationScheme = XML_BUFFER_ALLOC_DOUBLEIT;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    ret = unsafe { xmlBufferAllocSchemeThrDef };
    (unsafe { xmlBufferAllocSchemeThrDef = v });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn __xmlDefaultBufferSize() -> *mut i32 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlDefaultBufferSize };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlDefaultBufferSize };
    };
}
#[no_mangle]
pub extern "C" fn xmlThrDefDefaultBufferSize(mut v: i32) -> i32 {
    let mut ret: i32 = 0;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    ret = unsafe { xmlDefaultBufferSizeThrDef };
    (unsafe { xmlDefaultBufferSizeThrDef = v });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn __xmlDefaultSAXHandler() -> *mut xmlSAXHandlerV1 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlDefaultSAXHandler };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlDefaultSAXHandler };
    };
}
#[no_mangle]
pub extern "C" fn __xmlDefaultSAXLocator() -> *mut xmlSAXLocator {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlDefaultSAXLocator };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlDefaultSAXLocator };
    };
}
#[no_mangle]
pub extern "C" fn __xmlDoValidityCheckingDefaultValue() -> *mut i32 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlDoValidityCheckingDefaultValue };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlDoValidityCheckingDefaultValue };
    };
}
#[no_mangle]
pub extern "C" fn xmlThrDefDoValidityCheckingDefaultValue(mut v: i32) -> i32 {
    let mut ret: i32 = 0;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    ret = unsafe { xmlDoValidityCheckingDefaultValueThrDef };
    (unsafe { xmlDoValidityCheckingDefaultValueThrDef = v });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn __xmlGenericError() -> *mut xmlGenericErrorFunc {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlGenericError };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlGenericError };
    };
}
#[no_mangle]
pub extern "C" fn __xmlStructuredError() -> *mut xmlStructuredErrorFunc {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlStructuredError };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlStructuredError };
    };
}
#[no_mangle]
pub extern "C" fn __xmlGenericErrorContext() -> *mut *mut libc::c_void {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlGenericErrorContext };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlGenericErrorContext };
    };
}
#[no_mangle]
pub extern "C" fn __xmlStructuredErrorContext() -> *mut *mut libc::c_void {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlStructuredErrorContext };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlStructuredErrorContext };
    };
}
#[no_mangle]
pub extern "C" fn __xmlGetWarningsDefaultValue() -> *mut i32 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlGetWarningsDefaultValue };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlGetWarningsDefaultValue };
    };
}
#[no_mangle]
pub extern "C" fn xmlThrDefGetWarningsDefaultValue(mut v: i32) -> i32 {
    let mut ret: i32 = 0;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    ret = unsafe { xmlGetWarningsDefaultValueThrDef };
    (unsafe { xmlGetWarningsDefaultValueThrDef = v });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn __xmlIndentTreeOutput() -> *mut i32 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlIndentTreeOutput };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlIndentTreeOutput };
    };
}
#[no_mangle]
pub extern "C" fn xmlThrDefIndentTreeOutput(mut v: i32) -> i32 {
    let mut ret: i32 = 0;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    ret = unsafe { xmlIndentTreeOutputThrDef };
    (unsafe { xmlIndentTreeOutputThrDef = v });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn __xmlTreeIndentString() -> *mut *const i8 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlTreeIndentString };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlTreeIndentString };
    };
}
#[no_mangle]
pub extern "C" fn xmlThrDefTreeIndentString(mut v: *const i8) -> *const i8 {
    let mut ret: *const i8 = 0 as *const i8;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    ret = unsafe { xmlTreeIndentStringThrDef };
    (unsafe { xmlTreeIndentStringThrDef = v });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn __xmlKeepBlanksDefaultValue() -> *mut i32 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlKeepBlanksDefaultValue };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlKeepBlanksDefaultValue };
    };
}
#[no_mangle]
pub extern "C" fn xmlThrDefKeepBlanksDefaultValue(mut v: i32) -> i32 {
    let mut ret: i32 = 0;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    ret = unsafe { xmlKeepBlanksDefaultValueThrDef };
    (unsafe { xmlKeepBlanksDefaultValueThrDef = v });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn __xmlLineNumbersDefaultValue() -> *mut i32 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlLineNumbersDefaultValue };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlLineNumbersDefaultValue };
    };
}
#[no_mangle]
pub extern "C" fn xmlThrDefLineNumbersDefaultValue(mut v: i32) -> i32 {
    let mut ret: i32 = 0;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    ret = unsafe { xmlLineNumbersDefaultValueThrDef };
    (unsafe { xmlLineNumbersDefaultValueThrDef = v });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn __xmlLoadExtDtdDefaultValue() -> *mut i32 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlLoadExtDtdDefaultValue };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlLoadExtDtdDefaultValue };
    };
}
#[no_mangle]
pub extern "C" fn xmlThrDefLoadExtDtdDefaultValue(mut v: i32) -> i32 {
    let mut ret: i32 = 0;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    ret = unsafe { xmlLoadExtDtdDefaultValueThrDef };
    (unsafe { xmlLoadExtDtdDefaultValueThrDef = v });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn __xmlParserDebugEntities() -> *mut i32 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlParserDebugEntities };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlParserDebugEntities };
    };
}
#[no_mangle]
pub extern "C" fn xmlThrDefParserDebugEntities(mut v: i32) -> i32 {
    let mut ret: i32 = 0;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    ret = unsafe { xmlParserDebugEntitiesThrDef };
    (unsafe { xmlParserDebugEntitiesThrDef = v });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn __xmlParserVersion() -> *mut *const i8 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlParserVersion };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlParserVersion };
    };
}
#[no_mangle]
pub extern "C" fn __xmlPedanticParserDefaultValue() -> *mut i32 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlPedanticParserDefaultValue };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlPedanticParserDefaultValue };
    };
}
#[no_mangle]
pub extern "C" fn xmlThrDefPedanticParserDefaultValue(mut v: i32) -> i32 {
    let mut ret: i32 = 0;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    ret = unsafe { xmlPedanticParserDefaultValueThrDef };
    (unsafe { xmlPedanticParserDefaultValueThrDef = v });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn __xmlSaveNoEmptyTags() -> *mut i32 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlSaveNoEmptyTags };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlSaveNoEmptyTags };
    };
}
#[no_mangle]
pub extern "C" fn xmlThrDefSaveNoEmptyTags(mut v: i32) -> i32 {
    let mut ret: i32 = 0;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    ret = unsafe { xmlSaveNoEmptyTagsThrDef };
    (unsafe { xmlSaveNoEmptyTagsThrDef = v });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn __xmlSubstituteEntitiesDefaultValue() -> *mut i32 {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlSubstituteEntitiesDefaultValue };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlSubstituteEntitiesDefaultValue };
    };
}
#[no_mangle]
pub extern "C" fn xmlThrDefSubstituteEntitiesDefaultValue(mut v: i32) -> i32 {
    let mut ret: i32 = 0;
    (unsafe { xmlMutexLock(xmlThrDefMutex) });
    ret = unsafe { xmlSubstituteEntitiesDefaultValueThrDef };
    (unsafe { xmlSubstituteEntitiesDefaultValueThrDef = v });
    (unsafe { xmlMutexUnlock(xmlThrDefMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn __xmlRegisterNodeDefaultValue() -> *mut xmlRegisterNodeFunc {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlRegisterNodeDefaultValue };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlRegisterNodeDefaultValue };
    };
}
#[no_mangle]
pub extern "C" fn __xmlDeregisterNodeDefaultValue() -> *mut xmlDeregisterNodeFunc {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlDeregisterNodeDefaultValue };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlDeregisterNodeDefaultValue };
    };
}
#[no_mangle]
pub extern "C" fn __xmlParserInputBufferCreateFilenameValue(
) -> *mut xmlParserInputBufferCreateFilenameFunc {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlParserInputBufferCreateFilenameValue };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlParserInputBufferCreateFilenameValue };
    };
}
#[no_mangle]
pub extern "C" fn __xmlOutputBufferCreateFilenameValue() -> *mut xmlOutputBufferCreateFilenameFunc {
    if (unsafe { xmlIsMainThread() }) != 0 {
        return unsafe { &mut xmlOutputBufferCreateFilenameValue };
    } else {
        return unsafe { &mut (*(xmlGetGlobalState as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlOutputBufferCreateFilenameValue };
    };
}
