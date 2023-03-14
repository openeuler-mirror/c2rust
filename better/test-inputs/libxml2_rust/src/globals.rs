use ::libc;
extern "C" {
    pub type _xmlBuf;
    pub type _xmlDict;
    pub type _xmlMutex;
    fn __xmlGlobalInitMutexDestroy();
    fn xmlCharStrdup(cur: *const libc::c_char) -> *mut xmlChar;
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    static mut __xmlRegisterCallbacks: libc::c_int;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn xmlParserError(ctx: *mut libc::c_void, msg: *const libc::c_char, _: ...);
    fn xmlParserWarning(ctx: *mut libc::c_void, msg: *const libc::c_char, _: ...);
    fn xmlResetError(err: xmlErrorPtr);
    fn __xmlParserInputBufferCreateFilename(
        URI: *const libc::c_char,
        enc: xmlCharEncoding,
    ) -> xmlParserInputBufferPtr;
    fn __xmlOutputBufferCreateFilename(
        URI: *const libc::c_char,
        encoder: xmlCharEncodingHandlerPtr,
        compression: libc::c_int,
    ) -> xmlOutputBufferPtr;
    fn xmlSAX2GetPublicId(ctx: *mut libc::c_void) -> *const xmlChar;
    fn xmlSAX2GetSystemId(ctx: *mut libc::c_void) -> *const xmlChar;
    fn xmlSAX2SetDocumentLocator(ctx: *mut libc::c_void, loc: xmlSAXLocatorPtr);
    fn xmlSAX2GetLineNumber(ctx: *mut libc::c_void) -> libc::c_int;
    fn xmlSAX2GetColumnNumber(ctx: *mut libc::c_void) -> libc::c_int;
    fn xmlSAX2IsStandalone(ctx: *mut libc::c_void) -> libc::c_int;
    fn xmlSAX2HasInternalSubset(ctx: *mut libc::c_void) -> libc::c_int;
    fn xmlSAX2HasExternalSubset(ctx: *mut libc::c_void) -> libc::c_int;
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
    fn xmlSAX2GetParameterEntity(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
    ) -> xmlEntityPtr;
    fn xmlSAX2ResolveEntity(
        ctx: *mut libc::c_void,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
    ) -> xmlParserInputPtr;
    fn xmlSAX2EntityDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: libc::c_int,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
        content: *mut xmlChar,
    );
    fn xmlSAX2AttributeDecl(
        ctx: *mut libc::c_void,
        elem: *const xmlChar,
        fullname: *const xmlChar,
        type_0: libc::c_int,
        def: libc::c_int,
        defaultValue: *const xmlChar,
        tree: xmlEnumerationPtr,
    );
    fn xmlSAX2ElementDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: libc::c_int,
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
    fn xmlSAX2Characters(ctx: *mut libc::c_void, ch: *const xmlChar, len: libc::c_int);
    fn xmlSAX2IgnorableWhitespace(
        ctx: *mut libc::c_void,
        ch: *const xmlChar,
        len: libc::c_int,
    );
    fn xmlSAX2ProcessingInstruction(
        ctx: *mut libc::c_void,
        target: *const xmlChar,
        data: *const xmlChar,
    );
    fn xmlSAX2Comment(ctx: *mut libc::c_void, value: *const xmlChar);
    fn xmlSAX2CDataBlock(
        ctx: *mut libc::c_void,
        value: *const xmlChar,
        len: libc::c_int,
    );
    fn xmlNewMutex() -> xmlMutexPtr;
    fn xmlFreeMutex(tok: xmlMutexPtr);
    fn xmlMutexLock(tok: xmlMutexPtr);
    fn xmlMutexUnlock(tok: xmlMutexPtr);
    fn xmlIsMainThread() -> libc::c_int;
    fn xmlGetGlobalState() -> xmlGlobalStatePtr;
    fn initxmlDefaultSAXHandler(hdlr: *mut xmlSAXHandlerV1, warning: libc::c_int);
    fn inithtmlDefaultSAXHandler(hdlr: *mut xmlSAXHandlerV1);
    fn xmlGenericErrorDefaultFunc(
        ctx: *mut libc::c_void,
        msg: *const libc::c_char,
        _: ...
    );
}
pub type xmlChar = libc::c_uchar;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInputBuffer {
    pub context: *mut libc::c_void,
    pub readcallback: xmlInputReadCallback,
    pub closecallback: xmlInputCloseCallback,
    pub encoder: xmlCharEncodingHandlerPtr,
    pub buffer: xmlBufPtr,
    pub raw: xmlBufPtr,
    pub compressed: libc::c_int,
    pub error: libc::c_int,
    pub rawconsumed: libc::c_ulong,
}
pub type xmlBufPtr = *mut xmlBuf;
pub type xmlBuf = _xmlBuf;
pub type xmlCharEncodingHandlerPtr = *mut xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = _xmlCharEncodingHandler;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlCharEncodingHandler {
    pub name: *mut libc::c_char,
    pub input: xmlCharEncodingInputFunc,
    pub output: xmlCharEncodingOutputFunc,
    pub iconv_in: iconv_t,
    pub iconv_out: iconv_t,
}
pub type iconv_t = *mut libc::c_void;
pub type xmlCharEncodingOutputFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_uchar,
        *mut libc::c_int,
        *const libc::c_uchar,
        *mut libc::c_int,
    ) -> libc::c_int,
>;
pub type xmlCharEncodingInputFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_uchar,
        *mut libc::c_int,
        *const libc::c_uchar,
        *mut libc::c_int,
    ) -> libc::c_int,
>;
pub type xmlInputCloseCallback = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type xmlInputReadCallback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut libc::c_char,
        libc::c_int,
    ) -> libc::c_int,
>;
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
    pub written: libc::c_int,
    pub error: libc::c_int,
}
pub type xmlOutputCloseCallback = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type xmlOutputWriteCallback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_char,
        libc::c_int,
    ) -> libc::c_int,
>;
pub type xmlOutputBuffer = _xmlOutputBuffer;
pub type xmlOutputBufferPtr = *mut xmlOutputBuffer;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInput {
    pub buf: xmlParserInputBufferPtr,
    pub filename: *const libc::c_char,
    pub directory: *const libc::c_char,
    pub base: *const xmlChar,
    pub cur: *const xmlChar,
    pub end: *const xmlChar,
    pub length: libc::c_int,
    pub line: libc::c_int,
    pub col: libc::c_int,
    pub consumed: libc::c_ulong,
    pub free: xmlParserInputDeallocate,
    pub encoding: *const xmlChar,
    pub version: *const xmlChar,
    pub standalone: libc::c_int,
    pub id: libc::c_int,
}
pub type xmlParserInputDeallocate = Option::<unsafe extern "C" fn(*mut xmlChar) -> ()>;
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
    pub line: libc::c_ushort,
    pub extra: libc::c_ushort,
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
    pub name: *mut libc::c_char,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlNode,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub compression: libc::c_int,
    pub standalone: libc::c_int,
    pub intSubset: *mut _xmlDtd,
    pub extSubset: *mut _xmlDtd,
    pub oldNs: *mut _xmlNs,
    pub version: *const xmlChar,
    pub encoding: *const xmlChar,
    pub ids: *mut libc::c_void,
    pub refs: *mut libc::c_void,
    pub URL: *const xmlChar,
    pub charset: libc::c_int,
    pub dict: *mut _xmlDict,
    pub psvi: *mut libc::c_void,
    pub parseFlags: libc::c_int,
    pub properties: libc::c_int,
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
pub type xmlElementType = libc::c_uint;
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
pub type xmlAttributeType = libc::c_uint;
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
    pub domain: libc::c_int,
    pub code: libc::c_int,
    pub message: *mut libc::c_char,
    pub level: xmlErrorLevel,
    pub file: *mut libc::c_char,
    pub line: libc::c_int,
    pub str1: *mut libc::c_char,
    pub str2: *mut libc::c_char,
    pub str3: *mut libc::c_char,
    pub int1: libc::c_int,
    pub int2: libc::c_int,
    pub ctxt: *mut libc::c_void,
    pub node: *mut libc::c_void,
}
pub type xmlErrorLevel = libc::c_uint;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlNodePtr = *mut xmlNode;
pub type xmlNode = _xmlNode;
pub type xmlStructuredErrorFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> (),
>;
pub type xmlErrorPtr = *mut xmlError;
pub type externalSubsetSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type cdataBlockSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
>;
pub type getParameterEntitySAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
>;
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
    pub length: libc::c_int,
    pub etype: xmlEntityType,
    pub ExternalID: *const xmlChar,
    pub SystemID: *const xmlChar,
    pub nexte: *mut _xmlEntity,
    pub URI: *const xmlChar,
    pub owner: libc::c_int,
    pub checked: libc::c_int,
}
pub type xmlEntityType = libc::c_uint;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type errorSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type warningSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type commentSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
>;
pub type processingInstructionSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> (),
>;
pub type ignorableWhitespaceSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
>;
pub type charactersSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
>;
pub type referenceSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
>;
pub type endElementSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
>;
pub type startElementSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *mut *const xmlChar) -> (),
>;
pub type endDocumentSAXFunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type startDocumentSAXFunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type setDocumentLocatorSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
>;
pub type xmlSAXLocatorPtr = *mut xmlSAXLocator;
pub type xmlSAXLocator = _xmlSAXLocator;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXLocator {
    pub getPublicId: Option::<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getSystemId: Option::<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getLineNumber: Option::<unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int>,
    pub getColumnNumber: Option::<
        unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    >,
}
pub type unparsedEntityDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type elementDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        libc::c_int,
        xmlElementContentPtr,
    ) -> (),
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
pub type xmlElementContentOccur = libc::c_uint;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub type xmlElementContentType = libc::c_uint;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub type attributeDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        libc::c_int,
        libc::c_int,
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
pub type notationDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type entityDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        libc::c_int,
        *const xmlChar,
        *const xmlChar,
        *mut xmlChar,
    ) -> (),
>;
pub type getEntitySAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
>;
pub type resolveEntitySAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
    ) -> xmlParserInputPtr,
>;
pub type hasExternalSubsetSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type hasInternalSubsetSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type isStandaloneSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type internalSubsetSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type xmlBufferAllocationScheme = libc::c_uint;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
pub type xmlGenericErrorFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
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
    pub initialized: libc::c_uint,
}
pub type xmlSAXHandlerV1 = _xmlSAXHandlerV1;
pub type xmlCharEncoding = libc::c_int;
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
pub type xmlFreeFunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type xmlMallocFunc = Option::<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type xmlReallocFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
>;
pub type xmlStrdupFunc = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
>;
pub type xmlMutexPtr = *mut xmlMutex;
pub type xmlMutex = _xmlMutex;
pub type xmlParserInputBufferCreateFilenameFunc = Option::<
    unsafe extern "C" fn(*const libc::c_char, xmlCharEncoding) -> xmlParserInputBufferPtr,
>;
pub type xmlOutputBufferCreateFilenameFunc = Option::<
    unsafe extern "C" fn(
        *const libc::c_char,
        xmlCharEncodingHandlerPtr,
        libc::c_int,
    ) -> xmlOutputBufferPtr,
>;
pub type xmlRegisterNodeFunc = Option::<unsafe extern "C" fn(xmlNodePtr) -> ()>;
pub type xmlDeregisterNodeFunc = Option::<unsafe extern "C" fn(xmlNodePtr) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlGlobalState {
    pub xmlParserVersion: *const libc::c_char,
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
    pub oldXMLWDcompatibility: libc::c_int,
    pub xmlBufferAllocScheme: xmlBufferAllocationScheme,
    pub xmlDefaultBufferSize: libc::c_int,
    pub xmlSubstituteEntitiesDefaultValue: libc::c_int,
    pub xmlDoValidityCheckingDefaultValue: libc::c_int,
    pub xmlGetWarningsDefaultValue: libc::c_int,
    pub xmlKeepBlanksDefaultValue: libc::c_int,
    pub xmlLineNumbersDefaultValue: libc::c_int,
    pub xmlLoadExtDtdDefaultValue: libc::c_int,
    pub xmlParserDebugEntities: libc::c_int,
    pub xmlPedanticParserDefaultValue: libc::c_int,
    pub xmlSaveNoEmptyTags: libc::c_int,
    pub xmlIndentTreeOutput: libc::c_int,
    pub xmlTreeIndentString: *const libc::c_char,
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
pub unsafe extern "C" fn xmlInitGlobals() {
    if xmlThrDefMutex.is_null() {
        xmlThrDefMutex = xmlNewMutex();
    }
}
#[no_mangle]
pub static mut xmlFree: xmlFreeFunc = unsafe {
    Some(free as unsafe extern "C" fn(*mut libc::c_void) -> ())
};
#[no_mangle]
pub static mut xmlMalloc: xmlMallocFunc = unsafe {
    Some(malloc as unsafe extern "C" fn(libc::c_ulong) -> *mut libc::c_void)
};
#[no_mangle]
pub static mut xmlMallocAtomic: xmlMallocFunc = unsafe {
    Some(malloc as unsafe extern "C" fn(libc::c_ulong) -> *mut libc::c_void)
};
#[no_mangle]
pub static mut xmlRealloc: xmlReallocFunc = unsafe {
    Some(
        realloc
            as unsafe extern "C" fn(
                *mut libc::c_void,
                libc::c_ulong,
            ) -> *mut libc::c_void,
    )
};
unsafe extern "C" fn xmlPosixStrdup(mut cur: *const libc::c_char) -> *mut libc::c_char {
    return xmlCharStrdup(cur) as *mut libc::c_char;
}
#[no_mangle]
pub static mut xmlMemStrdup: xmlStrdupFunc = unsafe {
    Some(
        xmlPosixStrdup as unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
    )
};
#[no_mangle]
pub static mut xmlParserVersion: *const libc::c_char = b"21000-GITv2.10.0\0" as *const u8
    as *const libc::c_char;
#[no_mangle]
pub static mut xmlBufferAllocScheme: xmlBufferAllocationScheme = XML_BUFFER_ALLOC_EXACT;
static mut xmlBufferAllocSchemeThrDef: xmlBufferAllocationScheme = XML_BUFFER_ALLOC_EXACT;
#[no_mangle]
pub static mut xmlDefaultBufferSize: libc::c_int = 4096 as libc::c_int;
static mut xmlDefaultBufferSizeThrDef: libc::c_int = 4096 as libc::c_int;
#[no_mangle]
pub static mut oldXMLWDcompatibility: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut xmlParserDebugEntities: libc::c_int = 0 as libc::c_int;
static mut xmlParserDebugEntitiesThrDef: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut xmlDoValidityCheckingDefaultValue: libc::c_int = 0 as libc::c_int;
static mut xmlDoValidityCheckingDefaultValueThrDef: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut xmlGetWarningsDefaultValue: libc::c_int = 1 as libc::c_int;
static mut xmlGetWarningsDefaultValueThrDef: libc::c_int = 1 as libc::c_int;
#[no_mangle]
pub static mut xmlLoadExtDtdDefaultValue: libc::c_int = 0 as libc::c_int;
static mut xmlLoadExtDtdDefaultValueThrDef: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut xmlPedanticParserDefaultValue: libc::c_int = 0 as libc::c_int;
static mut xmlPedanticParserDefaultValueThrDef: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut xmlLineNumbersDefaultValue: libc::c_int = 0 as libc::c_int;
static mut xmlLineNumbersDefaultValueThrDef: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut xmlKeepBlanksDefaultValue: libc::c_int = 1 as libc::c_int;
static mut xmlKeepBlanksDefaultValueThrDef: libc::c_int = 1 as libc::c_int;
#[no_mangle]
pub static mut xmlSubstituteEntitiesDefaultValue: libc::c_int = 0 as libc::c_int;
static mut xmlSubstituteEntitiesDefaultValueThrDef: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut xmlRegisterNodeDefaultValue: xmlRegisterNodeFunc = None;
static mut xmlRegisterNodeDefaultValueThrDef: xmlRegisterNodeFunc = None;
#[no_mangle]
pub static mut xmlDeregisterNodeDefaultValue: xmlDeregisterNodeFunc = None;
static mut xmlDeregisterNodeDefaultValueThrDef: xmlDeregisterNodeFunc = None;
#[no_mangle]
pub static mut xmlParserInputBufferCreateFilenameValue: xmlParserInputBufferCreateFilenameFunc = None;
static mut xmlParserInputBufferCreateFilenameValueThrDef: xmlParserInputBufferCreateFilenameFunc = None;
#[no_mangle]
pub static mut xmlOutputBufferCreateFilenameValue: xmlOutputBufferCreateFilenameFunc = None;
static mut xmlOutputBufferCreateFilenameValueThrDef: xmlOutputBufferCreateFilenameFunc = None;
#[no_mangle]
pub static mut xmlGenericError: xmlGenericErrorFunc = unsafe {
    Some(
        xmlGenericErrorDefaultFunc
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    )
};
static mut xmlGenericErrorThrDef: xmlGenericErrorFunc = unsafe {
    Some(
        xmlGenericErrorDefaultFunc
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    )
};
#[no_mangle]
pub static mut xmlStructuredError: xmlStructuredErrorFunc = None;
static mut xmlStructuredErrorThrDef: xmlStructuredErrorFunc = None;
#[no_mangle]
pub static mut xmlGenericErrorContext: *mut libc::c_void = 0 as *const libc::c_void
    as *mut libc::c_void;
static mut xmlGenericErrorContextThrDef: *mut libc::c_void = 0 as *const libc::c_void
    as *mut libc::c_void;
#[no_mangle]
pub static mut xmlStructuredErrorContext: *mut libc::c_void = 0 as *const libc::c_void
    as *mut libc::c_void;
static mut xmlStructuredErrorContextThrDef: *mut libc::c_void = 0 as *const libc::c_void
    as *mut libc::c_void;
#[no_mangle]
pub static mut xmlLastError: xmlError = xmlError {
    domain: 0,
    code: 0,
    message: 0 as *const libc::c_char as *mut libc::c_char,
    level: XML_ERR_NONE,
    file: 0 as *const libc::c_char as *mut libc::c_char,
    line: 0,
    str1: 0 as *const libc::c_char as *mut libc::c_char,
    str2: 0 as *const libc::c_char as *mut libc::c_char,
    str3: 0 as *const libc::c_char as *mut libc::c_char,
    int1: 0,
    int2: 0,
    ctxt: 0 as *const libc::c_void as *mut libc::c_void,
    node: 0 as *const libc::c_void as *mut libc::c_void,
};
#[no_mangle]
pub static mut xmlIndentTreeOutput: libc::c_int = 1 as libc::c_int;
static mut xmlIndentTreeOutputThrDef: libc::c_int = 1 as libc::c_int;
#[no_mangle]
pub static mut xmlTreeIndentString: *const libc::c_char = b"  \0" as *const u8
    as *const libc::c_char;
static mut xmlTreeIndentStringThrDef: *const libc::c_char = b"  \0" as *const u8
    as *const libc::c_char;
#[no_mangle]
pub static mut xmlSaveNoEmptyTags: libc::c_int = 0 as libc::c_int;
static mut xmlSaveNoEmptyTagsThrDef: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut xmlDefaultSAXHandler: xmlSAXHandlerV1 = unsafe {
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
                xmlSAX2IsStandalone
                    as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
            ),
            hasInternalSubset: Some(
                xmlSAX2HasInternalSubset
                    as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
            ),
            hasExternalSubset: Some(
                xmlSAX2HasExternalSubset
                    as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
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
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> xmlEntityPtr,
            ),
            entityDecl: Some(
                xmlSAX2EntityDecl
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
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
                        libc::c_int,
                        libc::c_int,
                        *const xmlChar,
                        xmlEnumerationPtr,
                    ) -> (),
            ),
            elementDecl: Some(
                xmlSAX2ElementDecl
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
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
            endDocument: Some(
                xmlSAX2EndDocument as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            startElement: Some(
                xmlSAX2StartElement
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *mut *const xmlChar,
                    ) -> (),
            ),
            endElement: Some(
                xmlSAX2EndElement
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            reference: Some(
                xmlSAX2Reference
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            characters: Some(
                xmlSAX2Characters
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
            ),
            ignorableWhitespace: Some(
                xmlSAX2Characters
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
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
                xmlSAX2Comment
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            warning: Some(
                xmlParserWarning
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            error: Some(
                xmlParserError
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            fatalError: Some(
                xmlParserError
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            getParameterEntity: Some(
                xmlSAX2GetParameterEntity
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> xmlEntityPtr,
            ),
            cdataBlock: Some(
                xmlSAX2CDataBlock
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
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
            initialized: 0 as libc::c_int as libc::c_uint,
        };
        init
    }
};
#[no_mangle]
pub static mut xmlDefaultSAXLocator: xmlSAXLocator = unsafe {
    {
        let mut init = _xmlSAXLocator {
            getPublicId: Some(
                xmlSAX2GetPublicId
                    as unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar,
            ),
            getSystemId: Some(
                xmlSAX2GetSystemId
                    as unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar,
            ),
            getLineNumber: Some(
                xmlSAX2GetLineNumber
                    as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
            ),
            getColumnNumber: Some(
                xmlSAX2GetColumnNumber
                    as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
            ),
        };
        init
    }
};
#[no_mangle]
pub static mut htmlDefaultSAXHandler: xmlSAXHandlerV1 = unsafe {
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
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> xmlEntityPtr,
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
            endDocument: Some(
                xmlSAX2EndDocument as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            startElement: Some(
                xmlSAX2StartElement
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *mut *const xmlChar,
                    ) -> (),
            ),
            endElement: Some(
                xmlSAX2EndElement
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            reference: None,
            characters: Some(
                xmlSAX2Characters
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
            ),
            ignorableWhitespace: Some(
                xmlSAX2IgnorableWhitespace
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
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
                xmlSAX2Comment
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            warning: Some(
                xmlParserWarning
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            error: Some(
                xmlParserError
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            fatalError: Some(
                xmlParserError
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            getParameterEntity: Some(
                xmlSAX2GetParameterEntity
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> xmlEntityPtr,
            ),
            cdataBlock: Some(
                xmlSAX2CDataBlock
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
            ),
            externalSubset: None,
            initialized: 0 as libc::c_int as libc::c_uint,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn xmlInitializeGlobalState(mut gs: xmlGlobalStatePtr) {
    if xmlThrDefMutex.is_null() {
        xmlInitGlobals();
    }
    xmlMutexLock(xmlThrDefMutex);
    inithtmlDefaultSAXHandler(&mut (*gs).htmlDefaultSAXHandler);
    (*gs).oldXMLWDcompatibility = 0 as libc::c_int;
    (*gs).xmlBufferAllocScheme = xmlBufferAllocSchemeThrDef;
    (*gs).xmlDefaultBufferSize = xmlDefaultBufferSizeThrDef;
    initxmlDefaultSAXHandler(&mut (*gs).xmlDefaultSAXHandler, 1 as libc::c_int);
    let ref mut fresh0 = (*gs).xmlDefaultSAXLocator.getPublicId;
    *fresh0 = Some(
        xmlSAX2GetPublicId as unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar,
    );
    let ref mut fresh1 = (*gs).xmlDefaultSAXLocator.getSystemId;
    *fresh1 = Some(
        xmlSAX2GetSystemId as unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar,
    );
    let ref mut fresh2 = (*gs).xmlDefaultSAXLocator.getLineNumber;
    *fresh2 = Some(
        xmlSAX2GetLineNumber as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    );
    let ref mut fresh3 = (*gs).xmlDefaultSAXLocator.getColumnNumber;
    *fresh3 = Some(
        xmlSAX2GetColumnNumber as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    );
    (*gs).xmlDoValidityCheckingDefaultValue = xmlDoValidityCheckingDefaultValueThrDef;
    let ref mut fresh4 = (*gs).xmlFree;
    *fresh4 = ::std::mem::transmute::<
        Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
        xmlFreeFunc,
    >(Some(free as unsafe extern "C" fn(*mut libc::c_void) -> ()));
    let ref mut fresh5 = (*gs).xmlMalloc;
    *fresh5 = ::std::mem::transmute::<
        Option::<unsafe extern "C" fn(libc::c_ulong) -> *mut libc::c_void>,
        xmlMallocFunc,
    >(Some(malloc as unsafe extern "C" fn(libc::c_ulong) -> *mut libc::c_void));
    let ref mut fresh6 = (*gs).xmlMallocAtomic;
    *fresh6 = ::std::mem::transmute::<
        Option::<unsafe extern "C" fn(libc::c_ulong) -> *mut libc::c_void>,
        xmlMallocFunc,
    >(Some(malloc as unsafe extern "C" fn(libc::c_ulong) -> *mut libc::c_void));
    let ref mut fresh7 = (*gs).xmlRealloc;
    *fresh7 = ::std::mem::transmute::<
        Option::<
            unsafe extern "C" fn(*mut libc::c_void, libc::c_ulong) -> *mut libc::c_void,
        >,
        xmlReallocFunc,
    >(
        Some(
            realloc
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    libc::c_ulong,
                ) -> *mut libc::c_void,
        ),
    );
    let ref mut fresh8 = (*gs).xmlMemStrdup;
    *fresh8 = ::std::mem::transmute::<
        Option::<unsafe extern "C" fn(*const xmlChar) -> *mut xmlChar>,
        xmlStrdupFunc,
    >(Some(xmlStrdup as unsafe extern "C" fn(*const xmlChar) -> *mut xmlChar));
    (*gs).xmlGetWarningsDefaultValue = xmlGetWarningsDefaultValueThrDef;
    (*gs).xmlIndentTreeOutput = xmlIndentTreeOutputThrDef;
    let ref mut fresh9 = (*gs).xmlTreeIndentString;
    *fresh9 = xmlTreeIndentStringThrDef;
    (*gs).xmlKeepBlanksDefaultValue = xmlKeepBlanksDefaultValueThrDef;
    (*gs).xmlLineNumbersDefaultValue = xmlLineNumbersDefaultValueThrDef;
    (*gs).xmlLoadExtDtdDefaultValue = xmlLoadExtDtdDefaultValueThrDef;
    (*gs).xmlParserDebugEntities = xmlParserDebugEntitiesThrDef;
    let ref mut fresh10 = (*gs).xmlParserVersion;
    *fresh10 = b"21000\0" as *const u8 as *const libc::c_char;
    (*gs).xmlPedanticParserDefaultValue = xmlPedanticParserDefaultValueThrDef;
    (*gs).xmlSaveNoEmptyTags = xmlSaveNoEmptyTagsThrDef;
    (*gs).xmlSubstituteEntitiesDefaultValue = xmlSubstituteEntitiesDefaultValueThrDef;
    let ref mut fresh11 = (*gs).xmlGenericError;
    *fresh11 = xmlGenericErrorThrDef;
    let ref mut fresh12 = (*gs).xmlStructuredError;
    *fresh12 = xmlStructuredErrorThrDef;
    let ref mut fresh13 = (*gs).xmlGenericErrorContext;
    *fresh13 = xmlGenericErrorContextThrDef;
    let ref mut fresh14 = (*gs).xmlStructuredErrorContext;
    *fresh14 = xmlStructuredErrorContextThrDef;
    let ref mut fresh15 = (*gs).xmlRegisterNodeDefaultValue;
    *fresh15 = xmlRegisterNodeDefaultValueThrDef;
    let ref mut fresh16 = (*gs).xmlDeregisterNodeDefaultValue;
    *fresh16 = xmlDeregisterNodeDefaultValueThrDef;
    let ref mut fresh17 = (*gs).xmlParserInputBufferCreateFilenameValue;
    *fresh17 = xmlParserInputBufferCreateFilenameValueThrDef;
    let ref mut fresh18 = (*gs).xmlOutputBufferCreateFilenameValue;
    *fresh18 = xmlOutputBufferCreateFilenameValueThrDef;
    memset(
        &mut (*gs).xmlLastError as *mut xmlError as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlError>() as libc::c_ulong,
    );
    xmlMutexUnlock(xmlThrDefMutex);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCleanupGlobals() {
    xmlResetError(&mut xmlLastError);
    if !xmlThrDefMutex.is_null() {
        xmlFreeMutex(xmlThrDefMutex);
        xmlThrDefMutex = 0 as xmlMutexPtr;
    }
    __xmlGlobalInitMutexDestroy();
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefSetGenericErrorFunc(
    mut ctx: *mut libc::c_void,
    mut handler: xmlGenericErrorFunc,
) {
    xmlMutexLock(xmlThrDefMutex);
    xmlGenericErrorContextThrDef = ctx;
    if handler.is_some() {
        xmlGenericErrorThrDef = handler;
    } else {
        xmlGenericErrorThrDef = Some(
            xmlGenericErrorDefaultFunc
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
    }
    xmlMutexUnlock(xmlThrDefMutex);
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefSetStructuredErrorFunc(
    mut ctx: *mut libc::c_void,
    mut handler: xmlStructuredErrorFunc,
) {
    xmlMutexLock(xmlThrDefMutex);
    xmlStructuredErrorContextThrDef = ctx;
    xmlStructuredErrorThrDef = handler;
    xmlMutexUnlock(xmlThrDefMutex);
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegisterNodeDefault(
    mut func: xmlRegisterNodeFunc,
) -> xmlRegisterNodeFunc {
    let mut old: xmlRegisterNodeFunc = xmlRegisterNodeDefaultValue;
    __xmlRegisterCallbacks = 1 as libc::c_int;
    xmlRegisterNodeDefaultValue = func;
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefRegisterNodeDefault(
    mut func: xmlRegisterNodeFunc,
) -> xmlRegisterNodeFunc {
    let mut old: xmlRegisterNodeFunc = None;
    xmlMutexLock(xmlThrDefMutex);
    old = xmlRegisterNodeDefaultValueThrDef;
    __xmlRegisterCallbacks = 1 as libc::c_int;
    xmlRegisterNodeDefaultValueThrDef = func;
    xmlMutexUnlock(xmlThrDefMutex);
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDeregisterNodeDefault(
    mut func: xmlDeregisterNodeFunc,
) -> xmlDeregisterNodeFunc {
    let mut old: xmlDeregisterNodeFunc = xmlDeregisterNodeDefaultValue;
    __xmlRegisterCallbacks = 1 as libc::c_int;
    xmlDeregisterNodeDefaultValue = func;
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefDeregisterNodeDefault(
    mut func: xmlDeregisterNodeFunc,
) -> xmlDeregisterNodeFunc {
    let mut old: xmlDeregisterNodeFunc = None;
    xmlMutexLock(xmlThrDefMutex);
    old = xmlDeregisterNodeDefaultValueThrDef;
    __xmlRegisterCallbacks = 1 as libc::c_int;
    xmlDeregisterNodeDefaultValueThrDef = func;
    xmlMutexUnlock(xmlThrDefMutex);
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefParserInputBufferCreateFilenameDefault(
    mut func: xmlParserInputBufferCreateFilenameFunc,
) -> xmlParserInputBufferCreateFilenameFunc {
    let mut old: xmlParserInputBufferCreateFilenameFunc = None;
    xmlMutexLock(xmlThrDefMutex);
    old = xmlParserInputBufferCreateFilenameValueThrDef;
    if old.is_none() {
        old = Some(
            __xmlParserInputBufferCreateFilename
                as unsafe extern "C" fn(
                    *const libc::c_char,
                    xmlCharEncoding,
                ) -> xmlParserInputBufferPtr,
        );
    }
    xmlParserInputBufferCreateFilenameValueThrDef = func;
    xmlMutexUnlock(xmlThrDefMutex);
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefOutputBufferCreateFilenameDefault(
    mut func: xmlOutputBufferCreateFilenameFunc,
) -> xmlOutputBufferCreateFilenameFunc {
    let mut old: xmlOutputBufferCreateFilenameFunc = None;
    xmlMutexLock(xmlThrDefMutex);
    old = xmlOutputBufferCreateFilenameValueThrDef;
    if old.is_none() {
        old = Some(
            __xmlOutputBufferCreateFilename
                as unsafe extern "C" fn(
                    *const libc::c_char,
                    xmlCharEncodingHandlerPtr,
                    libc::c_int,
                ) -> xmlOutputBufferPtr,
        );
    }
    xmlOutputBufferCreateFilenameValueThrDef = func;
    xmlMutexUnlock(xmlThrDefMutex);
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn __htmlDefaultSAXHandler() -> *mut xmlSAXHandlerV1 {
    if xmlIsMainThread() != 0 {
        return &mut htmlDefaultSAXHandler
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .htmlDefaultSAXHandler
    };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlLastError() -> *mut xmlError {
    if xmlIsMainThread() != 0 {
        return &mut xmlLastError
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlLastError
    };
}
#[no_mangle]
pub unsafe extern "C" fn __oldXMLWDcompatibility() -> *mut libc::c_int {
    if xmlIsMainThread() != 0 {
        return &mut oldXMLWDcompatibility
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .oldXMLWDcompatibility
    };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlBufferAllocScheme() -> *mut xmlBufferAllocationScheme {
    if xmlIsMainThread() != 0 {
        return &mut xmlBufferAllocScheme
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlBufferAllocScheme
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefBufferAllocScheme(
    mut v: xmlBufferAllocationScheme,
) -> xmlBufferAllocationScheme {
    let mut ret: xmlBufferAllocationScheme = XML_BUFFER_ALLOC_DOUBLEIT;
    xmlMutexLock(xmlThrDefMutex);
    ret = xmlBufferAllocSchemeThrDef;
    xmlBufferAllocSchemeThrDef = v;
    xmlMutexUnlock(xmlThrDefMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlDefaultBufferSize() -> *mut libc::c_int {
    if xmlIsMainThread() != 0 {
        return &mut xmlDefaultBufferSize
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlDefaultBufferSize
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefDefaultBufferSize(mut v: libc::c_int) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    xmlMutexLock(xmlThrDefMutex);
    ret = xmlDefaultBufferSizeThrDef;
    xmlDefaultBufferSizeThrDef = v;
    xmlMutexUnlock(xmlThrDefMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlDefaultSAXHandler() -> *mut xmlSAXHandlerV1 {
    if xmlIsMainThread() != 0 {
        return &mut xmlDefaultSAXHandler
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlDefaultSAXHandler
    };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlDefaultSAXLocator() -> *mut xmlSAXLocator {
    if xmlIsMainThread() != 0 {
        return &mut xmlDefaultSAXLocator
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlDefaultSAXLocator
    };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlDoValidityCheckingDefaultValue() -> *mut libc::c_int {
    if xmlIsMainThread() != 0 {
        return &mut xmlDoValidityCheckingDefaultValue
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlDoValidityCheckingDefaultValue
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefDoValidityCheckingDefaultValue(
    mut v: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    xmlMutexLock(xmlThrDefMutex);
    ret = xmlDoValidityCheckingDefaultValueThrDef;
    xmlDoValidityCheckingDefaultValueThrDef = v;
    xmlMutexUnlock(xmlThrDefMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlGenericError() -> *mut xmlGenericErrorFunc {
    if xmlIsMainThread() != 0 {
        return &mut xmlGenericError
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlGenericError
    };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlStructuredError() -> *mut xmlStructuredErrorFunc {
    if xmlIsMainThread() != 0 {
        return &mut xmlStructuredError
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlStructuredError
    };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlGenericErrorContext() -> *mut *mut libc::c_void {
    if xmlIsMainThread() != 0 {
        return &mut xmlGenericErrorContext
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlGenericErrorContext
    };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlStructuredErrorContext() -> *mut *mut libc::c_void {
    if xmlIsMainThread() != 0 {
        return &mut xmlStructuredErrorContext
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlStructuredErrorContext
    };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlGetWarningsDefaultValue() -> *mut libc::c_int {
    if xmlIsMainThread() != 0 {
        return &mut xmlGetWarningsDefaultValue
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlGetWarningsDefaultValue
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefGetWarningsDefaultValue(
    mut v: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    xmlMutexLock(xmlThrDefMutex);
    ret = xmlGetWarningsDefaultValueThrDef;
    xmlGetWarningsDefaultValueThrDef = v;
    xmlMutexUnlock(xmlThrDefMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlIndentTreeOutput() -> *mut libc::c_int {
    if xmlIsMainThread() != 0 {
        return &mut xmlIndentTreeOutput
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlIndentTreeOutput
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefIndentTreeOutput(mut v: libc::c_int) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    xmlMutexLock(xmlThrDefMutex);
    ret = xmlIndentTreeOutputThrDef;
    xmlIndentTreeOutputThrDef = v;
    xmlMutexUnlock(xmlThrDefMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlTreeIndentString() -> *mut *const libc::c_char {
    if xmlIsMainThread() != 0 {
        return &mut xmlTreeIndentString
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlTreeIndentString
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefTreeIndentString(
    mut v: *const libc::c_char,
) -> *const libc::c_char {
    let mut ret: *const libc::c_char = 0 as *const libc::c_char;
    xmlMutexLock(xmlThrDefMutex);
    ret = xmlTreeIndentStringThrDef;
    xmlTreeIndentStringThrDef = v;
    xmlMutexUnlock(xmlThrDefMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlKeepBlanksDefaultValue() -> *mut libc::c_int {
    if xmlIsMainThread() != 0 {
        return &mut xmlKeepBlanksDefaultValue
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlKeepBlanksDefaultValue
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefKeepBlanksDefaultValue(
    mut v: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    xmlMutexLock(xmlThrDefMutex);
    ret = xmlKeepBlanksDefaultValueThrDef;
    xmlKeepBlanksDefaultValueThrDef = v;
    xmlMutexUnlock(xmlThrDefMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlLineNumbersDefaultValue() -> *mut libc::c_int {
    if xmlIsMainThread() != 0 {
        return &mut xmlLineNumbersDefaultValue
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlLineNumbersDefaultValue
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefLineNumbersDefaultValue(
    mut v: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    xmlMutexLock(xmlThrDefMutex);
    ret = xmlLineNumbersDefaultValueThrDef;
    xmlLineNumbersDefaultValueThrDef = v;
    xmlMutexUnlock(xmlThrDefMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlLoadExtDtdDefaultValue() -> *mut libc::c_int {
    if xmlIsMainThread() != 0 {
        return &mut xmlLoadExtDtdDefaultValue
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlLoadExtDtdDefaultValue
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefLoadExtDtdDefaultValue(
    mut v: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    xmlMutexLock(xmlThrDefMutex);
    ret = xmlLoadExtDtdDefaultValueThrDef;
    xmlLoadExtDtdDefaultValueThrDef = v;
    xmlMutexUnlock(xmlThrDefMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlParserDebugEntities() -> *mut libc::c_int {
    if xmlIsMainThread() != 0 {
        return &mut xmlParserDebugEntities
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlParserDebugEntities
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefParserDebugEntities(
    mut v: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    xmlMutexLock(xmlThrDefMutex);
    ret = xmlParserDebugEntitiesThrDef;
    xmlParserDebugEntitiesThrDef = v;
    xmlMutexUnlock(xmlThrDefMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlParserVersion() -> *mut *const libc::c_char {
    if xmlIsMainThread() != 0 {
        return &mut xmlParserVersion
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlParserVersion
    };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlPedanticParserDefaultValue() -> *mut libc::c_int {
    if xmlIsMainThread() != 0 {
        return &mut xmlPedanticParserDefaultValue
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlPedanticParserDefaultValue
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefPedanticParserDefaultValue(
    mut v: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    xmlMutexLock(xmlThrDefMutex);
    ret = xmlPedanticParserDefaultValueThrDef;
    xmlPedanticParserDefaultValueThrDef = v;
    xmlMutexUnlock(xmlThrDefMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlSaveNoEmptyTags() -> *mut libc::c_int {
    if xmlIsMainThread() != 0 {
        return &mut xmlSaveNoEmptyTags
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlSaveNoEmptyTags
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefSaveNoEmptyTags(mut v: libc::c_int) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    xmlMutexLock(xmlThrDefMutex);
    ret = xmlSaveNoEmptyTagsThrDef;
    xmlSaveNoEmptyTagsThrDef = v;
    xmlMutexUnlock(xmlThrDefMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlSubstituteEntitiesDefaultValue() -> *mut libc::c_int {
    if xmlIsMainThread() != 0 {
        return &mut xmlSubstituteEntitiesDefaultValue
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlSubstituteEntitiesDefaultValue
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlThrDefSubstituteEntitiesDefaultValue(
    mut v: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    xmlMutexLock(xmlThrDefMutex);
    ret = xmlSubstituteEntitiesDefaultValueThrDef;
    xmlSubstituteEntitiesDefaultValueThrDef = v;
    xmlMutexUnlock(xmlThrDefMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlRegisterNodeDefaultValue() -> *mut xmlRegisterNodeFunc {
    if xmlIsMainThread() != 0 {
        return &mut xmlRegisterNodeDefaultValue
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlRegisterNodeDefaultValue
    };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlDeregisterNodeDefaultValue() -> *mut xmlDeregisterNodeFunc {
    if xmlIsMainThread() != 0 {
        return &mut xmlDeregisterNodeDefaultValue
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlDeregisterNodeDefaultValue
    };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlParserInputBufferCreateFilenameValue() -> *mut xmlParserInputBufferCreateFilenameFunc {
    if xmlIsMainThread() != 0 {
        return &mut xmlParserInputBufferCreateFilenameValue
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlParserInputBufferCreateFilenameValue
    };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlOutputBufferCreateFilenameValue() -> *mut xmlOutputBufferCreateFilenameFunc {
    if xmlIsMainThread() != 0 {
        return &mut xmlOutputBufferCreateFilenameValue
    } else {
        return &mut (*(xmlGetGlobalState
            as unsafe extern "C" fn() -> xmlGlobalStatePtr)())
            .xmlOutputBufferCreateFilenameValue
    };
}
