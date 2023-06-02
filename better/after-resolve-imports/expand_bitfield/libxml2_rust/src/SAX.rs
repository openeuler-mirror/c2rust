use ::libc;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
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
pub use crate::src::SAX2::xmlSAX2GetEntity;
pub use crate::src::SAX2::xmlSAX2GetParameterEntity;
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
pub use crate::src::error::xmlParserError;
pub use crate::src::error::xmlParserWarning;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub type xmlChar = crate::src::HTMLparser::xmlChar;
// #[derive(Copy, Clone)]

pub type _xmlParserInputBuffer = crate::src::HTMLparser::_xmlParserInputBuffer;
pub type xmlBufPtr = crate::src::HTMLparser::xmlBufPtr;
pub type xmlBuf = crate::src::HTMLparser::xmlBuf;
pub type xmlCharEncodingHandlerPtr = crate::src::HTMLparser::xmlCharEncodingHandlerPtr;
pub type xmlCharEncodingHandler = crate::src::HTMLparser::xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub type _xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type iconv_t = crate::src::HTMLparser::iconv_t;
pub type xmlCharEncodingOutputFunc = crate::src::HTMLparser::xmlCharEncodingOutputFunc;
pub type xmlCharEncodingInputFunc = crate::src::HTMLparser::xmlCharEncodingInputFunc;
pub type xmlInputCloseCallback = crate::src::HTMLparser::xmlInputCloseCallback;
pub type xmlInputReadCallback = crate::src::HTMLparser::xmlInputReadCallback;
pub type xmlParserInputBuffer = crate::src::HTMLparser::xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = crate::src::HTMLparser::xmlParserInputBufferPtr;
// #[derive(Copy, Clone)]

pub type _xmlParserInput = crate::src::HTMLparser::_xmlParserInput;
pub type xmlParserInputDeallocate = crate::src::HTMLparser::xmlParserInputDeallocate;
pub type xmlParserInput = crate::src::HTMLparser::xmlParserInput;
pub type xmlParserInputPtr = crate::src::HTMLparser::xmlParserInputPtr;
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
pub type externalSubsetSAXFunc = crate::src::HTMLparser::externalSubsetSAXFunc;
pub type cdataBlockSAXFunc = crate::src::HTMLparser::cdataBlockSAXFunc;
pub type getParameterEntitySAXFunc = crate::src::HTMLparser::getParameterEntitySAXFunc;
pub type xmlEntityPtr = crate::src::HTMLparser::xmlEntityPtr;
pub type xmlEntity = crate::src::HTMLparser::xmlEntity;
// #[derive(Copy, Clone)]

pub type _xmlEntity = crate::src::HTMLparser::_xmlEntity;
pub type xmlEntityType = crate::src::HTMLparser::xmlEntityType;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = crate::src::HTMLparser::fatalErrorSAXFunc;
pub type errorSAXFunc = crate::src::HTMLparser::errorSAXFunc;
pub type warningSAXFunc = crate::src::HTMLparser::warningSAXFunc;
pub type commentSAXFunc = crate::src::HTMLparser::commentSAXFunc;
pub type processingInstructionSAXFunc = crate::src::HTMLparser::processingInstructionSAXFunc;
pub type ignorableWhitespaceSAXFunc = crate::src::HTMLparser::ignorableWhitespaceSAXFunc;
pub type charactersSAXFunc = crate::src::HTMLparser::charactersSAXFunc;
pub type referenceSAXFunc = crate::src::HTMLparser::referenceSAXFunc;
pub type endElementSAXFunc = crate::src::HTMLparser::endElementSAXFunc;
pub type startElementSAXFunc = crate::src::HTMLparser::startElementSAXFunc;
pub type endDocumentSAXFunc = crate::src::HTMLparser::endDocumentSAXFunc;
pub type startDocumentSAXFunc = crate::src::HTMLparser::startDocumentSAXFunc;
pub type setDocumentLocatorSAXFunc = crate::src::HTMLparser::setDocumentLocatorSAXFunc;
pub type xmlSAXLocatorPtr = crate::src::HTMLparser::xmlSAXLocatorPtr;
pub type xmlSAXLocator = crate::src::HTMLparser::xmlSAXLocator;
// #[derive(Copy, Clone)]

pub type _xmlSAXLocator = crate::src::HTMLparser::_xmlSAXLocator;
pub type unparsedEntityDeclSAXFunc = crate::src::HTMLparser::unparsedEntityDeclSAXFunc;
pub type elementDeclSAXFunc = crate::src::HTMLparser::elementDeclSAXFunc;
pub type xmlElementContentPtr = crate::src::HTMLparser::xmlElementContentPtr;
pub type xmlElementContent = crate::src::HTMLparser::xmlElementContent;
// #[derive(Copy, Clone)]

pub type _xmlElementContent = crate::src::HTMLparser::_xmlElementContent;
pub type xmlElementContentOccur = crate::src::HTMLparser::xmlElementContentOccur;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub type xmlElementContentType = crate::src::HTMLparser::xmlElementContentType;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub type attributeDeclSAXFunc = crate::src::HTMLparser::attributeDeclSAXFunc;
pub type xmlEnumerationPtr = crate::src::HTMLparser::xmlEnumerationPtr;
pub type xmlEnumeration = crate::src::HTMLparser::xmlEnumeration;
// #[derive(Copy, Clone)]

pub type _xmlEnumeration = crate::src::HTMLparser::_xmlEnumeration;
pub type notationDeclSAXFunc = crate::src::HTMLparser::notationDeclSAXFunc;
pub type entityDeclSAXFunc = crate::src::HTMLparser::entityDeclSAXFunc;
pub type getEntitySAXFunc = crate::src::HTMLparser::getEntitySAXFunc;
pub type resolveEntitySAXFunc = crate::src::HTMLparser::resolveEntitySAXFunc;
pub type hasExternalSubsetSAXFunc = crate::src::HTMLparser::hasExternalSubsetSAXFunc;
pub type hasInternalSubsetSAXFunc = crate::src::HTMLparser::hasInternalSubsetSAXFunc;
pub type isStandaloneSAXFunc = crate::src::HTMLparser::isStandaloneSAXFunc;
pub type internalSubsetSAXFunc = crate::src::HTMLparser::internalSubsetSAXFunc;
// #[derive(Copy, Clone)]

pub type _xmlSAXHandlerV1 = crate::src::HTMLparser::_xmlSAXHandlerV1;
pub type xmlSAXHandlerV1 = crate::src::HTMLparser::xmlSAXHandlerV1;
#[no_mangle]
pub unsafe extern "C" fn initxmlDefaultSAXHandler(
    mut hdlr: *mut xmlSAXHandlerV1,
    mut warning: i32,
) {
    if (*hdlr).initialized == 1 as i32 as u32 {
        return;
    }
    let fresh0 = &mut ((*hdlr).internalSubset);
    *fresh0 = Some(
        xmlSAX2InternalSubset
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh1 = &mut ((*hdlr).externalSubset);
    *fresh1 = Some(
        xmlSAX2ExternalSubset
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh2 = &mut ((*hdlr).isStandalone);
    *fresh2 = Some(
        xmlSAX2IsStandalone as unsafe extern "C" fn(*mut libc::c_void) -> i32,
    );
    let fresh3 = &mut ((*hdlr).hasInternalSubset);
    *fresh3 = Some(
        xmlSAX2HasInternalSubset
            as unsafe extern "C" fn(*mut libc::c_void) -> i32,
    );
    let fresh4 = &mut ((*hdlr).hasExternalSubset);
    *fresh4 = Some(
        xmlSAX2HasExternalSubset
            as unsafe extern "C" fn(*mut libc::c_void) -> i32,
    );
    let fresh5 = &mut ((*hdlr).resolveEntity);
    *fresh5 = Some(
        xmlSAX2ResolveEntity
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
            ) -> xmlParserInputPtr,
    );
    let fresh6 = &mut ((*hdlr).getEntity);
    *fresh6 = Some(
        xmlSAX2GetEntity
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
    );
    let fresh7 = &mut ((*hdlr).getParameterEntity);
    *fresh7 = Some(
        xmlSAX2GetParameterEntity
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
    );
    let fresh8 = &mut ((*hdlr).entityDecl);
    *fresh8 = Some(
        xmlSAX2EntityDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                i32,
                *const xmlChar,
                *const xmlChar,
                *mut xmlChar,
            ) -> (),
    );
    let fresh9 = &mut ((*hdlr).attributeDecl);
    *fresh9 = Some(
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
    );
    let fresh10 = &mut ((*hdlr).elementDecl);
    *fresh10 = Some(
        xmlSAX2ElementDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                i32,
                xmlElementContentPtr,
            ) -> (),
    );
    let fresh11 = &mut ((*hdlr).notationDecl);
    *fresh11 = Some(
        xmlSAX2NotationDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh12 = &mut ((*hdlr).unparsedEntityDecl);
    *fresh12 = Some(
        xmlSAX2UnparsedEntityDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh13 = &mut ((*hdlr).setDocumentLocator);
    *fresh13 = Some(
        xmlSAX2SetDocumentLocator
            as unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
    );
    let fresh14 = &mut ((*hdlr).startDocument);
    *fresh14 = Some(
        xmlSAX2StartDocument as unsafe extern "C" fn(*mut libc::c_void) -> (),
    );
    let fresh15 = &mut ((*hdlr).endDocument);
    *fresh15 = Some(xmlSAX2EndDocument as unsafe extern "C" fn(*mut libc::c_void) -> ());
    let fresh16 = &mut ((*hdlr).startElement);
    *fresh16 = Some(
        xmlSAX2StartElement
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *mut *const xmlChar,
            ) -> (),
    );
    let fresh17 = &mut ((*hdlr).endElement);
    *fresh17 = Some(
        xmlSAX2EndElement
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
    );
    let fresh18 = &mut ((*hdlr).reference);
    *fresh18 = Some(
        xmlSAX2Reference as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
    );
    let fresh19 = &mut ((*hdlr).characters);
    *fresh19 = Some(
        xmlSAX2Characters
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh20 = &mut ((*hdlr).cdataBlock);
    *fresh20 = Some(
        xmlSAX2CDataBlock
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh21 = &mut ((*hdlr).ignorableWhitespace);
    *fresh21 = Some(
        xmlSAX2Characters
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh22 = &mut ((*hdlr).processingInstruction);
    *fresh22 = Some(
        xmlSAX2ProcessingInstruction
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    if warning == 0 as i32 {
        let fresh23 = &mut ((*hdlr).warning);
        *fresh23 = None;
    } else {
        let fresh24 = &mut ((*hdlr).warning);
        *fresh24 = Some(
            xmlParserWarning
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const i8,
                    ...
                ) -> (),
        );
    }
    let fresh25 = &mut ((*hdlr).error);
    *fresh25 = Some(
        xmlParserError
            as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
    );
    let fresh26 = &mut ((*hdlr).fatalError);
    *fresh26 = Some(
        xmlParserError
            as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
    );
    (*hdlr).initialized = 1 as i32 as u32;
}
#[no_mangle]
pub unsafe extern "C" fn inithtmlDefaultSAXHandler(mut hdlr: *mut xmlSAXHandlerV1) {
    if (*hdlr).initialized == 1 as i32 as u32 {
        return;
    }
    let fresh27 = &mut ((*hdlr).internalSubset);
    *fresh27 = Some(
        xmlSAX2InternalSubset
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh28 = &mut ((*hdlr).externalSubset);
    *fresh28 = None;
    let fresh29 = &mut ((*hdlr).isStandalone);
    *fresh29 = None;
    let fresh30 = &mut ((*hdlr).hasInternalSubset);
    *fresh30 = None;
    let fresh31 = &mut ((*hdlr).hasExternalSubset);
    *fresh31 = None;
    let fresh32 = &mut ((*hdlr).resolveEntity);
    *fresh32 = None;
    let fresh33 = &mut ((*hdlr).getEntity);
    *fresh33 = Some(
        xmlSAX2GetEntity
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
    );
    let fresh34 = &mut ((*hdlr).getParameterEntity);
    *fresh34 = None;
    let fresh35 = &mut ((*hdlr).entityDecl);
    *fresh35 = None;
    let fresh36 = &mut ((*hdlr).attributeDecl);
    *fresh36 = None;
    let fresh37 = &mut ((*hdlr).elementDecl);
    *fresh37 = None;
    let fresh38 = &mut ((*hdlr).notationDecl);
    *fresh38 = None;
    let fresh39 = &mut ((*hdlr).unparsedEntityDecl);
    *fresh39 = None;
    let fresh40 = &mut ((*hdlr).setDocumentLocator);
    *fresh40 = Some(
        xmlSAX2SetDocumentLocator
            as unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
    );
    let fresh41 = &mut ((*hdlr).startDocument);
    *fresh41 = Some(
        xmlSAX2StartDocument as unsafe extern "C" fn(*mut libc::c_void) -> (),
    );
    let fresh42 = &mut ((*hdlr).endDocument);
    *fresh42 = Some(xmlSAX2EndDocument as unsafe extern "C" fn(*mut libc::c_void) -> ());
    let fresh43 = &mut ((*hdlr).startElement);
    *fresh43 = Some(
        xmlSAX2StartElement
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *mut *const xmlChar,
            ) -> (),
    );
    let fresh44 = &mut ((*hdlr).endElement);
    *fresh44 = Some(
        xmlSAX2EndElement
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
    );
    let fresh45 = &mut ((*hdlr).reference);
    *fresh45 = None;
    let fresh46 = &mut ((*hdlr).characters);
    *fresh46 = Some(
        xmlSAX2Characters
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh47 = &mut ((*hdlr).cdataBlock);
    *fresh47 = Some(
        xmlSAX2CDataBlock
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh48 = &mut ((*hdlr).ignorableWhitespace);
    *fresh48 = Some(
        xmlSAX2IgnorableWhitespace
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh49 = &mut ((*hdlr).processingInstruction);
    *fresh49 = Some(
        xmlSAX2ProcessingInstruction
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh50 = &mut ((*hdlr).comment);
    *fresh50 = Some(
        xmlSAX2Comment as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
    );
    let fresh51 = &mut ((*hdlr).warning);
    *fresh51 = Some(
        xmlParserWarning
            as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
    );
    let fresh52 = &mut ((*hdlr).error);
    *fresh52 = Some(
        xmlParserError
            as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
    );
    let fresh53 = &mut ((*hdlr).fatalError);
    *fresh53 = Some(
        xmlParserError
            as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
    );
    (*hdlr).initialized = 1 as i32 as u32;
}
