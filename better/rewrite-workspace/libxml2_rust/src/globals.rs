use ::libc;
extern "C" {
    
    
    
    
    
    
    static mut __xmlRegisterCallbacks: libc::c_int;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::SAX2::xmlSAX2AttributeDecl;
pub use crate::src::SAX2::xmlSAX2CDataBlock;
pub use crate::src::SAX2::xmlSAX2Characters;
pub use crate::src::SAX2::xmlSAX2Comment;
pub use crate::src::SAX2::xmlSAX2ElementDecl;
pub use crate::src::SAX2::xmlSAX2EndDocument;
pub use crate::src::SAX2::xmlSAX2EndElement;
pub use crate::src::SAX2::xmlSAX2EntityDecl;
pub use crate::src::SAX2::xmlSAX2ExternalSubset;
pub use crate::src::SAX2::xmlSAX2GetColumnNumber;
pub use crate::src::SAX2::xmlSAX2GetEntity;
pub use crate::src::SAX2::xmlSAX2GetLineNumber;
pub use crate::src::SAX2::xmlSAX2GetParameterEntity;
pub use crate::src::SAX2::xmlSAX2GetPublicId;
pub use crate::src::SAX2::xmlSAX2GetSystemId;
pub use crate::src::SAX2::xmlSAX2HasExternalSubset;
pub use crate::src::SAX2::xmlSAX2HasInternalSubset;
pub use crate::src::SAX2::xmlSAX2IgnorableWhitespace;
pub use crate::src::SAX2::xmlSAX2InternalSubset;
pub use crate::src::SAX2::xmlSAX2IsStandalone;
pub use crate::src::SAX2::xmlSAX2NotationDecl;
pub use crate::src::SAX2::xmlSAX2ProcessingInstruction;
pub use crate::src::SAX2::xmlSAX2Reference;
pub use crate::src::SAX2::xmlSAX2ResolveEntity;
pub use crate::src::SAX2::xmlSAX2SetDocumentLocator;
pub use crate::src::SAX2::xmlSAX2StartDocument;
pub use crate::src::SAX2::xmlSAX2StartElement;
pub use crate::src::SAX2::xmlSAX2UnparsedEntityDecl;
pub use crate::src::SAX::inithtmlDefaultSAXHandler;
pub use crate::src::SAX::initxmlDefaultSAXHandler;
pub use crate::src::error::xmlGenericErrorDefaultFunc;
pub use crate::src::error::xmlParserError;
pub use crate::src::error::xmlParserWarning;
pub use crate::src::error::xmlResetError;
pub use crate::src::threads::__xmlGlobalInitMutexDestroy;
pub use crate::src::threads::xmlFreeMutex;
pub use crate::src::threads::xmlGetGlobalState;
pub use crate::src::threads::xmlIsMainThread;
pub use crate::src::threads::xmlMutexLock;
pub use crate::src::threads::xmlMutexUnlock;
pub use crate::src::threads::xmlNewMutex;
pub use crate::src::xmlIO::__xmlOutputBufferCreateFilename;
pub use crate::src::xmlIO::__xmlParserInputBufferCreateFilename;
pub use crate::src::xmlstring::xmlCharStrdup;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub use crate::src::threads::_xmlMutex;
pub use crate::src::HTMLparser::xmlChar;
pub use crate::src::HTMLparser::size_t;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserInputBuffer;
pub use crate::src::HTMLparser::xmlBufPtr;
pub use crate::src::HTMLparser::xmlBuf;
pub use crate::src::HTMLparser::xmlCharEncodingHandlerPtr;
pub use crate::src::HTMLparser::xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlCharEncodingHandler;
pub use crate::src::HTMLparser::iconv_t;
pub use crate::src::HTMLparser::xmlCharEncodingOutputFunc;
pub use crate::src::HTMLparser::xmlCharEncodingInputFunc;
pub use crate::src::HTMLparser::xmlInputCloseCallback;
pub use crate::src::HTMLparser::xmlInputReadCallback;
pub use crate::src::HTMLparser::xmlParserInputBuffer;
pub use crate::src::HTMLparser::xmlParserInputBufferPtr;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLtree::_xmlOutputBuffer;
pub use crate::src::HTMLtree::xmlOutputCloseCallback;
pub use crate::src::HTMLtree::xmlOutputWriteCallback;
pub use crate::src::HTMLtree::xmlOutputBuffer;
pub use crate::src::HTMLtree::xmlOutputBufferPtr;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserInput;
pub use crate::src::HTMLparser::xmlParserInputDeallocate;
pub use crate::src::HTMLparser::xmlParserInput;
pub use crate::src::HTMLparser::xmlParserInputPtr;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlNode;
pub use crate::src::HTMLparser::xmlNs;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlNs;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlDoc;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlDtd;
pub use crate::src::HTMLparser::xmlElementType;
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
pub use crate::src::HTMLparser::xmlNsType;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlAttr;
pub use crate::src::HTMLparser::xmlAttributeType;
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
pub use crate::src::HTMLparser::xmlError;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlError;
pub use crate::src::HTMLparser::xmlErrorLevel;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub use crate::src::HTMLparser::xmlNodePtr;
pub use crate::src::HTMLparser::xmlNode;
pub use crate::src::HTMLparser::xmlStructuredErrorFunc;
pub use crate::src::HTMLparser::xmlErrorPtr;
pub use crate::src::HTMLparser::externalSubsetSAXFunc;
pub use crate::src::HTMLparser::cdataBlockSAXFunc;
pub use crate::src::HTMLparser::getParameterEntitySAXFunc;
pub use crate::src::HTMLparser::xmlEntityPtr;
pub use crate::src::HTMLparser::xmlEntity;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlEntity;
pub use crate::src::HTMLparser::xmlEntityType;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub use crate::src::HTMLparser::fatalErrorSAXFunc;
pub use crate::src::HTMLparser::errorSAXFunc;
pub use crate::src::HTMLparser::warningSAXFunc;
pub use crate::src::HTMLparser::commentSAXFunc;
pub use crate::src::HTMLparser::processingInstructionSAXFunc;
pub use crate::src::HTMLparser::ignorableWhitespaceSAXFunc;
pub use crate::src::HTMLparser::charactersSAXFunc;
pub use crate::src::HTMLparser::referenceSAXFunc;
pub use crate::src::HTMLparser::endElementSAXFunc;
pub use crate::src::HTMLparser::startElementSAXFunc;
pub use crate::src::HTMLparser::endDocumentSAXFunc;
pub use crate::src::HTMLparser::startDocumentSAXFunc;
pub use crate::src::HTMLparser::setDocumentLocatorSAXFunc;
pub use crate::src::HTMLparser::xmlSAXLocatorPtr;
pub use crate::src::HTMLparser::xmlSAXLocator;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlSAXLocator;
pub use crate::src::HTMLparser::unparsedEntityDeclSAXFunc;
pub use crate::src::HTMLparser::elementDeclSAXFunc;
pub use crate::src::HTMLparser::xmlElementContentPtr;
pub use crate::src::HTMLparser::xmlElementContent;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlElementContent;
pub use crate::src::HTMLparser::xmlElementContentOccur;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub use crate::src::HTMLparser::xmlElementContentType;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub use crate::src::HTMLparser::attributeDeclSAXFunc;
pub use crate::src::HTMLparser::xmlEnumerationPtr;
pub use crate::src::HTMLparser::xmlEnumeration;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlEnumeration;
pub use crate::src::HTMLparser::notationDeclSAXFunc;
pub use crate::src::HTMLparser::entityDeclSAXFunc;
pub use crate::src::HTMLparser::getEntitySAXFunc;
pub use crate::src::HTMLparser::resolveEntitySAXFunc;
pub use crate::src::HTMLparser::hasExternalSubsetSAXFunc;
pub use crate::src::HTMLparser::hasInternalSubsetSAXFunc;
pub use crate::src::HTMLparser::isStandaloneSAXFunc;
pub use crate::src::HTMLparser::internalSubsetSAXFunc;
pub use crate::src::HTMLtree::xmlBufferAllocationScheme;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
pub use crate::src::HTMLparser::xmlGenericErrorFunc;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlSAXHandlerV1;
pub use crate::src::HTMLparser::xmlSAXHandlerV1;
pub use crate::src::HTMLparser::xmlCharEncoding;
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
pub use crate::src::HTMLparser::xmlFreeFunc;
pub use crate::src::HTMLparser::xmlMallocFunc;
pub use crate::src::HTMLparser::xmlReallocFunc;
pub use crate::src::encoding::xmlStrdupFunc;
pub use crate::src::dict::xmlMutexPtr;
pub use crate::src::dict::xmlMutex;
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
pub use crate::src::HTMLparser::xmlRegisterNodeFunc;
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
